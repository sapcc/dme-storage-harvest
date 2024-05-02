package qospolicyfixed

import (
	"github.com/netapp/harvest/v2/cmd/collectors"
	"github.com/netapp/harvest/v2/cmd/poller/plugin"
	"github.com/netapp/harvest/v2/pkg/matrix"
	"github.com/netapp/harvest/v2/pkg/util"
)

var metrics = []string{
	"max_throughput_iops",
	"max_throughput_mbps",
	"min_throughput_iops",
	"min_throughput_mbps",
}

type QosPolicyFixed struct {
	*plugin.AbstractPlugin
}

func New(p *plugin.AbstractPlugin) plugin.Plugin {
	return &QosPolicyFixed{AbstractPlugin: p}
}

func (q *QosPolicyFixed) Run(dataMap map[string]*matrix.Matrix) ([]*matrix.Matrix, *util.Metadata, error) {
	// Change ZAPI max-throughput/min-throughput to match what REST publishes

	data := dataMap[q.Object]

	// create metrics
	for _, k := range metrics {
		err := matrix.CreateMetric(k, data)
		if err != nil {
			q.Logger.Error().Err(err).Str("key", k).Msg("error while creating metric")
			return nil, nil, err
		}
	}

	for _, instance := range data.GetInstances() {
		if !instance.IsExportable() {
			continue
		}
		policyClass := instance.GetLabel("class")
		if policyClass != "user_defined" {
			// Only export user_defined policy classes - ignore all others
			// REST only returns user_defined while ZAPI returns all
			instance.SetExportable(false)
			continue
		}
		collectors.SetThroughput(data, instance, "max_xput", "max_throughput_iops", "max_throughput_mbps", q.Logger)
		collectors.SetThroughput(data, instance, "min_xput", "min_throughput_iops", "min_throughput_mbps", q.Logger)
	}

	return nil, nil, nil
}
