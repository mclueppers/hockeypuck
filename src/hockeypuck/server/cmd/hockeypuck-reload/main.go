package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkg/errors"

	cf "hockeypuck/conflux"
	"hockeypuck/hkp/sks"
	"hockeypuck/hkp/storage"
	"hockeypuck/server"
	"hockeypuck/server/cmd"

	log "github.com/sirupsen/logrus"
)

var (
	configFile = flag.String("config", "", "config file")
	cpuProf    = flag.Bool("cpuprof", false, "enable CPU profiling")
	memProf    = flag.Bool("memprof", false, "enable mem profiling")
)

func main() {
	flag.Parse()

	var (
		settings *server.Settings
		err      error
	)
	if configFile != nil {
		conf, err := os.ReadFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration file '%s'.\n", *configFile)
			cmd.Die(errors.WithStack(err))
		}
		settings, err = server.ParseSettings(string(conf))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing configuration file '%s'.\n", *configFile)
			cmd.Die(errors.WithStack(err))
		}
	}

	cpuFile := cmd.StartCPUProf(*cpuProf, nil)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR2)
	go func() {
		for {
			select {
			case sig := <-c:
				switch sig {
				case syscall.SIGUSR2:
					cpuFile = cmd.StartCPUProf(*cpuProf, cpuFile)
					cmd.WriteMemProf(*memProf)
				}
			}
		}
	}()

	err = reload(settings)
	cmd.Die(err)
}

func reload(settings *server.Settings) error {
	st, err := server.DialStorage(settings)
	if err != nil {
		return errors.WithStack(err)
	}
	defer st.Close()

	ptree, err := sks.NewPrefixTree(settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings)
	if err != nil {
		return errors.WithStack(err)
	}
	err = ptree.Create()
	if err != nil {
		return errors.WithStack(err)
	}
	defer ptree.Close()

	statsFilename := sks.StatsFilename(settings.Conflux.Recon.LevelDB.Path)
	stats := sks.NewStats()
	err = stats.ReadFile(statsFilename)
	if err != nil {
		log.Warningf("failed to open stats file %q: %v", statsFilename, err)
		stats = sks.NewStats()
	}
	defer stats.WriteFile(statsFilename)

	st.Subscribe(func(kc storage.KeyChange) error {
		stats.Update(kc)
		ka, ok := kc.(storage.KeyAdded)
		if ok {
			var digestZp cf.Zp
			err := sks.DigestZp(ka.Digest, &digestZp)
			if err != nil {
				return errors.Wrapf(err, "bad digest %q", ka.Digest)
			}
			return ptree.Insert(&digestZp)
		}
		return nil
	})

	t := time.Now()
	u, err := st.Reload()
	if err != nil {
		log.Errorf("some keys failed to update: %v", err)
		if hke, ok := err.(storage.InsertError); ok {
			for _, err := range hke.Errors {
				log.Errorf("update error: %v", err)
			}
		}
	}
	if u > 0 {
		log.Infof("updated %d keys in %v", u, time.Since(t))
	}

	return nil
}
