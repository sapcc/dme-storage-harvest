/*
 * Copyright NetApp Inc, 2021 All rights reserved
 */
package main

import (
	"goharvest2/cmd/poller/exporter"
	"goharvest2/cmd/poller/options"
	"goharvest2/pkg/matrix"
	"goharvest2/pkg/tree/node"
	"testing"
)

// test rendering in debug mode
// this does not send to influxdb, but simply prints
// rendered data
func TestExportDebug(t *testing.T) {

	opts := &options.Options{}
	opts.Debug = true

	params := node.NewS("")
	params.NewChildS("addr", "localhost")
	params.NewChildS("org", "harvest")
	params.NewChildS("bucket", "harvest")
	params.NewChildS("token", "xxxxxxx")
	influx := New(exporter.New("InfluxDB", "influx-test", opts, params))
	if err := influx.Init(); err != nil {
		t.Fatal(err)
	}

	// matrix with fake data
	data := matrix.New("test_exporter", "influxd_test_data")
	data.SetExportOptions(matrix.DefaultExportOptions())

	// add metric
	m, err := data.NewMetricInt("test_metric")
	if err != nil {
		t.Fatal(err)
	}

	// add instance
	i, err := data.NewInstance("test_instance")
	if err != nil {
		t.Fatal(err)
	}
	i.SetLabel("test_label", "test_label_value")

	// add numeric data

	if err := m.SetValueInt(i, 42); err != nil {
		t.Fatal(err)
	}

	// render data
	if err := influx.Export(data); err != nil {
		t.Fatal(err)
	}
}

/* Uncomment to test against a running InfluxDB instance
   ! Edit the params values below
   ! Uncomment import "goharvest2/share/tree/node"
func TestExportProduction(t *testing.T) {

    logger.SetLevel(0)

    opts := &options.Options{}

    params := node.NewS("")
    params.NewChildS("addr", "")
    params.NewChildS("bucket", "")
    params.NewChildS("org", "")
    params.NewChildS("token", "")

    influx := New(exporter.New("InfluxDB", "influx-test", opts, params))

    if err := influx.Init(); err != nil {
        t.Fatal(err)
    }

    // matrix with fake data
    data := matrix.New("test_exporter", "influxd_test_data", "")
    data.SetExportOptions(matrix.DefaultExportOptions())

    // add metric
    m, err := data.AddMetric("test_metric", "test_metric", true)
    if err != nil {
        t.Fatal(err)
    }

    // add instance
    i, err := data.AddInstance("test_instance")
    if err != nil {
        t.Fatal(err)
    }
    i.Labels.Set("test_label", "test_label_value")

    // add numeric data
    if err := data.InitData(); err != nil {
        t.Fatal(err)
    }
    if err := data.SetValueString(m, i, "0"); err != nil {
        t.Fatal(err)
    }

    // render data
    if err := influx.Export(data); err != nil {
        t.Error(err)
    }
}
*/
