package router

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

func newMetricsReg() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())
	return reg
}

func regMetrics(r prometheus.Registerer, cs ...prometheus.Collector) error {
	for _, c := range cs {
		if err := r.Register(c); err != nil {
			return err
		}
	}
	return nil
}
