/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  Casey Marshall and Hockeypuck Contributors

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

package server

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"hockeypuck/hkp/storage"
)

var buckets = append(prometheus.DefBuckets, 30, 60, 300, 600, 1800, 3600)

var serverMetrics = struct {
	httpRequestDuration *prometheus.HistogramVec
	keysAdded           prometheus.Counter
	keysIgnored         prometheus.Counter
	keysUpdated         prometheus.Counter
	keysRemoved         prometheus.Counter
	keysAddedJitter     prometheus.Counter
	keysRemovedJitter   prometheus.Counter
}{
	httpRequestDuration: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "hockeypuck",
			Name:      "http_request_duration_seconds",
			Help:      "Time spent generating HTTP responses",
			Buckets:   buckets,
		},
		[]string{"method", "status_code"},
	),
	keysAdded: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_added",
			Help:      "New keys added since startup",
		},
	),
	keysIgnored: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_ignored",
			Help:      "Keys with no-op updates since startup",
		},
	),
	keysUpdated: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_updated",
			Help:      "Keys updated since startup",
		},
	),
	keysRemoved: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_removed",
			Help:      "Keys removed since startup",
		},
	),
	keysAddedJitter: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_added_jitter",
			Help:      "Lost PTree entries recreated since startup",
		},
	),
	keysRemovedJitter: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_removed_jitter",
			Help:      "Stale PTree entries cleaned up since startup",
		},
	),
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(serverMetrics.httpRequestDuration)
		prometheus.MustRegister(serverMetrics.keysAdded)
		prometheus.MustRegister(serverMetrics.keysIgnored)
		prometheus.MustRegister(serverMetrics.keysUpdated)
		prometheus.MustRegister(serverMetrics.keysRemoved)
		prometheus.MustRegister(serverMetrics.keysAddedJitter)
		prometheus.MustRegister(serverMetrics.keysRemovedJitter)
	})
}

func metricsStorageNotifier(kc storage.KeyChange) error {
	switch kc.(type) {
	case storage.KeyAdded:
		serverMetrics.keysAdded.Inc()
	case storage.KeyNotChanged:
		serverMetrics.keysIgnored.Inc()
	case storage.KeyReplaced:
		serverMetrics.keysUpdated.Inc()
	case storage.KeyRemoved:
		serverMetrics.keysRemoved.Inc()
	case storage.KeyAddedJitter:
		serverMetrics.keysAddedJitter.Inc()
	case storage.KeyRemovedJitter:
		serverMetrics.keysRemovedJitter.Inc()
	}
	return nil
}

func recordHTTPRequestDuration(method string, statusCode int, duration time.Duration) {
	serverMetrics.httpRequestDuration.WithLabelValues(method, strconv.Itoa(statusCode)).Observe(duration.Seconds())
}
