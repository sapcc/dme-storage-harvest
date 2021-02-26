package options

import (
	"fmt"
	"os"
    "strings"
	"goharvest2/share/options"
	"goharvest2/share/version"
)

type Options struct {
    Poller          string
    Daemon          bool
    Debug           bool
    PrometheusPort  string
    ConfPath        string
    HomePath        string
    LogPath         string
    PidPath         string
    LogLevel        int
    Version         string
    Hostname        string
}

func (o *Options) String() string {
    x := []string {
        fmt.Sprintf("%s= %s", "Poller", o.Poller),
        fmt.Sprintf("%s = %v", "Daemon", o.Daemon),
        fmt.Sprintf("%s = %v", "Debug", o.Debug),
        fmt.Sprintf("%s = %s", "PrometheusPort", o.PrometheusPort),
        fmt.Sprintf("%s = %d", "LogLevel", o.LogLevel),
        fmt.Sprintf("%s = %s", "HomePath", o.HomePath),
        fmt.Sprintf("%s = %s", "ConfPath", o.ConfPath),
        fmt.Sprintf("%s = %s", "LogPath", o.LogPath),
        fmt.Sprintf("%s = %s", "PidPath", o.PidPath),
        fmt.Sprintf("%s = %s", "Hostname", o.Hostname),
        fmt.Sprintf("%s = %s", "Version", o.Version),
    }
    return strings.Join(x, ", ")
}

func (o *Options) Print() {
    fmt.Println(o.String())
}

func GetOpts() (*Options, string)  {
	var args Options
    args = Options{}

    // set defaults
    args.Daemon = false
    args.Debug = false
    args.LogLevel = 2
    args.Version = version.VERSION
    hostname, _ := os.Hostname()
    args.Hostname = hostname

    if args.HomePath = os.Getenv("HARVEST_HOME"); args.HomePath == "" {
        args.HomePath = "/opt/harvest/"
    }
    if args.ConfPath = os.Getenv("HARVEST_CONF"); args.ConfPath == "" {
        args.ConfPath = "/etc/harvest/"
    }
    if args.LogPath = os.Getenv("HARVEST_LOGS"); args.LogPath == "" {
        args.LogPath = "/var/log/harvest/"
    }
    if args.PidPath = os.Getenv("HARVEST_PIDS"); args.PidPath == "" {
        args.PidPath = "/var/run/harvest/"
    }

    // parse from command line
    parser := options.New("Harvest Poller", "poller", "Runs collectors and exporters for a target system")
    parser.String(&args.Poller, "poller", "p", "Poller name as defined in config")
    parser.Bool(&args.Debug, "debug", "d", "Debug mode, no data will be exported")
    parser.Bool(&args.Daemon, "daemon", "", "Start as daemon")
    parser.Int(&args.LogLevel, "loglevel", "l", "Logging level (0=trace, 1=debug, 2=info, 3=warning, 4=error, 5=critical)")

    ok := parser.Parse()

    if !ok {
        os.Exit(1)
    }

    if args.Poller == "" {
        fmt.Println("Missing required argument: poller")
        os.Exit(1)
    }

    args.Print()

    return &args, args.Poller
}
