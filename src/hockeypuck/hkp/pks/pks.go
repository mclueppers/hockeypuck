/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pks

import (
	"bytes"
	"net"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"

	"hockeypuck/hkp/storage"
)

// Max delay backoff multiplier when there are SMTP errors.
const maxDelay = 60

// Status of PKS synchronization
type Status struct {
	// Address of the PKS server.
	Addr string
	// Timestamp of the last sync to this server.
	LastSync time.Time
	// Error message of last sync failure.
	LastError string
}

type Config struct {
	From string     `toml:"from"`
	To   []string   `toml:"to"`
	SMTP SMTPConfig `toml:"smtp"`
}

const (
	DefaultSMTPHost = "localhost:25"
)

type SMTPConfig struct {
	Host     string `toml:"host"`
	ID       string `toml:"id"`
	User     string `toml:"user"`
	Password string `toml:"pass"`
}

// Storage implements a simple interface to persist the status of multiple PKS peers.
// All methods are prefixed by `PKS` so that a concrete storage class can implement multiple Storage interfaces.
// NB: PKSInit() MUST be called with lastSync == time.Now() to prevent an update storm on startup.
type Storage interface {
	PKSInit(addr string, lastSync time.Time) error // Initialise a new PKS peer
	PKSAll() ([]Status, error)                     // Return the status of all PKS peers
	PKSUpdate(status Status) error                 // Update the status of one PKS peer
	PKSRemove(addr string) error                   // Remove one PKS peer
	PKSGet(addr string) error                      // Return the status of one PKS peer
}

// Basic implementation of outbound PKS synchronization
type Sender struct {
	config     *Config
	hkpStorage storage.Storage
	pksStorage Storage
	smtpAuth   smtp.Auth

	t tomb.Tomb
}

// Initialize from command line switches if fields not set.
func NewSender(hkpStorage storage.Storage, pksStorage Storage, config *Config) (*Sender, error) {
	if config == nil {
		return nil, errors.New("PKS synchronization not configured")
	}

	sender := &Sender{
		config:     config,
		hkpStorage: hkpStorage,
		pksStorage: pksStorage,
	}

	var err error
	authHost := sender.config.SMTP.Host
	if parts := strings.Split(authHost, ":"); len(parts) >= 1 {
		// Strip off the port, use only the hostname for auth
		authHost, _, err = net.SplitHostPort(authHost)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	sender.smtpAuth = smtp.PlainAuth(
		sender.config.SMTP.ID,
		sender.config.SMTP.User,
		sender.config.SMTP.Password, authHost)

	err = sender.initStatus()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sender, nil
}

func (sender *Sender) initStatus() error {
	for _, addr := range sender.config.To {
		err := sender.pksStorage.PKSInit(addr, time.Now())
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func (sender *Sender) SendKeys(status Status) error {
	uuids, err := sender.hkpStorage.ModifiedSince(status.LastSync)
	if err != nil {
		return errors.WithStack(err)
	}

	keys, err := sender.hkpStorage.FetchKeyrings(uuids)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, key := range keys {
		// Send key email
		log.Debugf("sending key %q to PKS %s", key.PrimaryKey.Fingerprint(), status.Addr)
		err = sender.SendKey(status.Addr, key.PrimaryKey)
		status.LastError = err.Error()
		if err != nil {
			log.Errorf("error sending key to PKS %s: %v", status.Addr, err)
			storageErr := sender.pksStorage.PKSUpdate(status)
			if storageErr != nil {
				return errors.WithStack(storageErr)
			}
			return errors.WithStack(err)
		}
		// Send successful, update the timestamp accordingly
		status.LastSync = key.MTime
		err = sender.pksStorage.PKSUpdate(status)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// Send an updated public key to a PKS server.
func (sender *Sender) SendKey(addr string, key *openpgp.PrimaryKey) error {
	var msg bytes.Buffer
	emailMatch := regexp.MustCompile("^(mailto:)?([^@]+@[^@]+)$")
	matches := emailMatch.FindStringSubmatch(addr)
	if matches != nil && matches[2] != "" {
		emailAddr := matches[2]
		msg.WriteString("Subject: ADD\n\n")
		openpgp.WriteArmoredPackets(&msg, []*openpgp.PrimaryKey{key})
		return smtp.SendMail(sender.config.SMTP.Host, sender.smtpAuth,
			sender.config.From, []string{emailAddr}, msg.Bytes())
	}
	return errors.Errorf("PKS address '%s' not supported", addr)
}

// Notify PKS downstream servers
func (sender *Sender) run() error {
	delay := 1
	timer := time.NewTimer(time.Duration(delay) * time.Minute)
	for {
		select {
		case <-sender.t.Dying():
			return nil
		case <-timer.C:
		}

		statuses, err := sender.pksStorage.PKSAll()
		if err != nil {
			log.Errorf("failed to obtain PKS sync status: %v", err)
			goto DELAY
		}
		for _, status := range statuses {
			err = sender.SendKeys(status)
			if err != nil {
				// Increase delay backoff
				delay++
				if delay > maxDelay {
					delay = maxDelay
				}
				break
			} else {
				// Successful mail sent, reset delay
				delay = 1
			}
		}

	DELAY:
		toSleep := time.Duration(delay) * time.Minute
		if delay > 1 {
			// log delay if we had an error
			log.Debugf("PKS sleeping %d minute(s)", toSleep)
		}
		timer.Reset(toSleep)
	}
}

// Report status of all PKS peers
func (sender *Sender) Status() ([]Status, error) {
	statuses, err := sender.pksStorage.PKSAll()
	if err != nil {
		return nil, errors.Errorf("failed to obtain PKS sync status: %v", err)
	}
	return statuses, nil
}

// Start PKS synchronization
func (sender *Sender) Start() {
	sender.t.Go(sender.run)
}

func (sender *Sender) Stop() error {
	sender.t.Kill(nil)
	return sender.t.Wait()
}
