package main

import (
	"runtime"
	"sync"
	"os"
	"os/signal"
	"syscall"
	"strconv"
	"path"
	"plugin"
	"strings"
    "goharvest2/share/logger"
    "goharvest2/share/util"
    "goharvest2/share/config"
    "goharvest2/share/errors"
	"goharvest2/share/tree/node"
	"goharvest2/poller/schedule"
	"goharvest2/poller/collector"
	"goharvest2/poller/exporter"
	"goharvest2/poller/options"
)

var SIGNALS = []os.Signal{
			syscall.SIGHUP,
			syscall.SIGINT,
			syscall.SIGTERM,
			syscall.SIGQUIT,
}

type Poller struct {
	Name string
	prefix string
	options *options.Options
	pid int
	pidf string
	schedule *schedule.Schedule
	collectors []collector.Collector
	exporters []exporter.Exporter
	exporter_params *node.Node
	params *node.Node
	//metadata *metadata.Metadata
}

func New() *Poller {
	return &Poller{}
}

func (p *Poller) Init() error {

	var err error
	// Set poller main attributes
	p.options, p.Name = options.GetOpts()

	p.prefix = "(poller) (" + p.Name + ")"

	// If daemon, make sure handler outputs to file
	if p.options.Daemon {
		err := logger.OpenFileOutput(p.options.LogPath, "poller_" + p.Name + ".log")
		if err != nil {
			return err
		}
	}

	if err = logger.SetLevel(p.options.LogLevel); err != nil {
		logger.Warn(p.prefix, "using default loglevel=2 (info): %s", err.Error())
	}

	// Useful info for debugging
	if p.options.Debug {
		logger.Info(p.prefix, "using options: %s%v%s", util.Pink, p.options.String(), util.End)
		p.LogDebugInfo()
	}

	signal_channel := make(chan os.Signal, 1)
	signal.Notify(signal_channel, SIGNALS...)
	go p.handleSignals(signal_channel)
	logger.Debug(p.prefix, "Set signal handler for %v", SIGNALS)

	// Write PID to file
	err = p.registerPid()
	if err != nil {
		logger.Warn(p.prefix, "Failed to write PID file: %v", err)
	}

	// Announce startup
	if p.options.Daemon {
		logger.Info(p.prefix, "Starting as daemon [pid=%d] [pid file=%s]", p.pid, p.pidf)
	} else {
		logger.Info(p.prefix, "Starting in foreground [pid=%d] [pid file=%s]", p.pid, p.pidf)
	}

	// Load poller parameters and exporters from config
	if p.params, err = config.GetPoller(p.options.ConfPath, "harvest.yml", p.Name); err != nil {
		logger.Error(p.prefix, "read config: %v", err)
		return err
	}

	// Prometheus port used to be defined in the exporter parameters as a range
	// this leads to rarely happening bugs, so we will transition to definig
	// the port at the poller-level
	p.options.PrometheusPort = p.params.GetChildContentS("prometheus_port")

	if p.exporter_params, err = config.GetExporters(p.options.ConfPath, "harvest.yml"); err != nil {
		logger.Warn(p.prefix, "read exporters from config")
		// @TODO just warn or abort?
	}

	if collectors := p.params.GetChildS("collectors"); collectors != nil {
		for _, c := range collectors.GetAllChildContentS() {
			if err = p.load_collector(c, ""); err != nil {
				logger.Error(p.prefix, "initializing collector [%s]: %v", c, err)
			}
		}
	} else {
		logger.Warn(p.prefix, "No collectors defined for poller")
		return errors.New(errors.ERR_NO_COLLECTOR, "No collectors")
	}

	if len(p.collectors) == 0 {
		logger.Warn(p.prefix, "No collectors initialized, stopping")
		return errors.New(errors.ERR_NO_COLLECTOR, "No collectors")
	}
	logger.Debug(p.prefix, "Initialized %d collectors", len(p.collectors))
	
	if len(p.exporters) == 0 {
		logger.Warn(p.prefix, "No exporters initialized, continuing without exporters")
	} else {
		logger.Debug(p.prefix, "Initialized %d exporters", len(p.exporters))
	}

	//@todo interval from config
	p.schedule = schedule.New()
	if err := p.schedule.AddTaskString("poller", "60s", nil); err != nil {
		logger.Error(p.prefix, "Setting schedule: %v", err)
		return err
	}

	// Famous last words 
	logger.Info(p.prefix, "Poller start-up complete.")

	return nil

}

func (p *Poller) load_collector(class, object string) error {

	var err error
	var sym plugin.Symbol
	var binpath string
	var template *node.Node
	var subcollectors []collector.Collector

	binpath = path.Join(p.options.HomePath, "bin", "collectors")

	if sym, err = util.LoadFuncFromModule(binpath, strings.ToLower(class), "New"); err != nil {
		return err
	}

	NewFunc, ok := sym.(func(*collector.AbstractCollector) collector.Collector)
	if !ok {
		return errors.New(errors.ERR_DLOAD, "New() has not expected signature")
	}

	if template, err = collector.ImportTemplate(p.options.ConfPath, class); err != nil {
		return err
	} else if template == nil {  // probably redundant
		return errors.New(errors.MISSING_PARAM, "collector template")
	}
	// log: imported and merged template...
	template.Union(p.params)

	// if we don't know object, try load from template
	if object == "" {
		object = template.GetChildContentS("object")
	}

	// if object is defined, we only initialize 1 subcollector / object
	if object != "" {
		c := NewFunc(collector.New(class, object, p.options, template.Copy()))
		if err = c.Init(); err != nil {
			return err
		} else {
			subcollectors = append(subcollectors, c)
			logger.Debug(p.prefix, "initialized collector [%s:%s]", class, object)
		}
	// if template has list of objects, initialiez 1 subcollector for each
	} else if objects := template.GetChildS("objects"); objects != nil {
		for _, object := range objects.GetChildren() {
			c := NewFunc(collector.New(class, object.GetNameS(), p.options, template.Copy()))
			if err = c.Init(); err != nil {
				return err
			} else {
				subcollectors = append(subcollectors, c)
				logger.Debug(p.prefix, "initialized subcollector [%s:%s]", class, object.GetNameS())
			}
		}
	} else {
		return errors.New(errors.MISSING_PARAM, "collector object")
	}

	p.collectors = append(p.collectors, subcollectors...)
	logger.Debug(p.prefix, "initialized [%s] with %d subcollectors", class, len(subcollectors))

	// link each collector with requested exporter
	for _, c := range subcollectors {
		for _, e := range c.WantedExporters() {
			if exp := p.load_exporter(e); exp != nil {
				c.LinkExporter(exp)
				logger.Debug(p.prefix, "Linked [%s:%s] to exporter [%s]", c.GetName(), c.GetObject(), e)
			} else {
				logger.Warn(p.prefix, "Exporter [%s] requested by [%s:%s] not available", e, c.GetName(), c.GetObject())
			}
		}
	}
	return nil
}


func (p *Poller) get_exporter(name string) exporter.Exporter {
	for _, exp := range p.exporters {
		if exp.GetName() == name {
			return exp
		}
	}
	return nil
}

// @TODO return error
func (p *Poller) load_exporter(name string) exporter.Exporter {

	var err error
	var sym plugin.Symbol
	var binpath, class string
	var params *node.Node

	// stop here if exporter is already loaded
	if e := p.get_exporter(name); e != nil {
		return e
	}

	if params = p.exporter_params.GetChildS(name); params == nil {
		logger.Warn(p.prefix, "Exporter [%s] not defined in config", name)
		return nil
	}

	if class = params.GetChildContentS("exporter"); class == "" {
		logger.Warn(p.prefix, "Exporter [%s] missing field \"exporter\"", name)
		return nil
	}

	binpath = path.Join(p.options.HomePath, "bin", "exporters")

	if sym, err = util.LoadFuncFromModule(binpath, strings.ToLower(class), "New"); err != nil {
		logger.Error(p.prefix, err.Error())
		return nil
	}

	NewFunc, ok := sym.(func(*exporter.AbstractExporter) exporter.Exporter)
	if !ok {
		logger.Error(p.prefix, "New() has not expected signature")
		return nil
	}

	e := NewFunc(exporter.New(class, name, p.options, params))
	if err = e.Init(); err != nil {
		logger.Error(p.prefix, "Failed initializing exporter [%s]: %v", name, err)
		return nil
	}

	p.exporters = append(p.exporters, e)
	logger.Info(p.prefix, "Initialized exporter [%s]", name)
	return e
	
}

func (p *Poller) Start() {

	var wg sync.WaitGroup

	/* Start collectors */
	for _, col := range p.collectors {
		logger.Debug(p.prefix, "Starting collector [%s]", col.GetName())
		wg.Add(1)
		go col.Start(&wg)
	}

	go p.selfMonitor()

	wg.Wait()
	//time.Sleep(30 * time.Second)

	logger.Info(p.prefix, "No active collectors. Poller terminating.")
	p.Stop()

	//os.Exit(0)
	return
}

func (p *Poller) Stop() {
	logger.Info(p.prefix, "Cleaning up and stopping Poller [pid=%d]", p.pid)

	if p.options.Daemon {

		var err error

		err = os.Remove(p.pidf)
		if err != nil {
			logger.Warn(p.prefix, "Failed to clean pid file: %v", err)
		} else {
			logger.Debug(p.prefix, "Clean pid file [%s]", p.pidf)
		}

		err = logger.CloseFileOutput()
		if err != nil {
			logger.Error(p.prefix, "Failed to close log file: %v", err)
		}
	}
}

func (p *Poller) selfMonitor() {

	task, _ := p.schedule.GetTask("poller")

	for {

		if task.IsDue() {

			task.Start()

			up_collectors := 0
			up_exporters := 0

			for _, c := range p.collectors {
				code, status, msg := c.GetStatus()
				logger.Debug(p.prefix, "status of collector [%s]: %d (%s) %s", c.GetName(), code, status, msg)
				if code == 1 {
					up_collectors += 1
				}
			}

			for _, e := range p.exporters {
				code, status, msg := e.GetStatus()
				logger.Debug(p.prefix, "status of exporter [%s]: %d (%s) %s", e.GetName(), code, status, msg)
				if code == 1 {
					up_exporters += 1
				}
			}

			logger.Info(p.prefix, "Updated status: %d up collectors (of %d) and %d up exporters (of %d)", up_collectors, len(p.collectors), up_exporters, len(p.exporters))

		}
		
		p.schedule.Sleep()

	}
}

func (p *Poller) handleSignals(signal_channel chan os.Signal) {
	for {
		sig := <-signal_channel
		logger.Info(p.prefix, "Caught signal [%s]", sig)
		p.Stop()
		os.Exit(0)
	}
}

func (p *Poller) handleFifo() {
	logger.Info(p.prefix, "Serving APIs for Harvest2 daemon")
	for {
		;
	}
}

func (p *Poller) registerPid() error {
	var err error
	p.pid = os.Getpid()
	if p.options.Daemon {
		var file *os.File
		p.pidf = path.Join(p.options.PidPath, p.Name + ".pid")
		file, err = os.Create(p.pidf)
		if err == nil {
			_, err = file.WriteString(strconv.Itoa(p.pid))
			if err == nil {
				file.Sync()
			}
			file.Close()
		}
	}
	return err
}

func (p *Poller) LogDebugInfo() {

	var st syscall.Sysinfo_t

	logger.Debug(p.prefix, "Running on [%s]: system [%s], arch [%s], CPUs=%d", 
		p.options.Hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	logger.Debug(p.prefix, "Poller Go build version [%s]", runtime.Version())
	
	st = syscall.Sysinfo_t{}
	if syscall.Sysinfo(&st) == nil {
		logger.Debug(p.prefix, "System uptime [%d], Memory [%d] / Free [%d]. Running processes [%d]", 
			st.Uptime, st.Totalram, st.Freeram, st.Procs)
	}
}


func main() {

    p := New()

    if err := p.Init(); err == nil {

		p.Start()

	} else {
		p.Stop()
	}
}
