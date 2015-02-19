package daemon

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"

	"github.com/docker/docker/daemon/networkdriver"
	"github.com/docker/docker/opts"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/libcontainer/security/seccomp"
)

const (
	defaultNetworkMtu    = 1500
	disableNetworkBridge = "none"
)

// Config define the configuration of a docker daemon
// These are the configuration settings that you pass
// to the docker daemon when you launch it with say: `docker -d -e lxc`
// FIXME: separate runtime configuration from http api configuration
type Config struct {
	Pidfile                     string
	Root                        string
	AutoRestart                 bool
	Dns                         []string
	DnsSearch                   []string
	EnableIPv6                  bool
	EnableIptables              bool
	EnableIpForward             bool
	EnableIpMasq                bool
	DefaultIp                   net.IP
	BridgeIface                 string
	BridgeIP                    string
	FixedCIDR                   string
	FixedCIDRv6                 string
	InterContainerCommunication bool
	GraphDriver                 string
	GraphOptions                []string
	ExecDriver                  string
	Mtu                         int
	SocketGroup                 string
	EnableCors                  bool
	DisableNetwork              bool
	EnableSelinuxSupport        bool
	Context                     map[string][]string
	TrustKeyPath                string
	Labels                      []string
	SeccompConfigPath           string
	SeccompConfig               seccomp.SeccompConfig
}

// InstallFlags adds command-line options to the top-level flag parser for
// the current process.
// Subsequent calls to `flag.Parse` will populate config with values parsed
// from the command-line.
func (config *Config) InstallFlags() {
	flag.StringVar(&config.Pidfile, []string{"p", "-pidfile"}, "/var/run/docker.pid", "Path to use for daemon PID file")
	flag.StringVar(&config.Root, []string{"g", "-graph"}, "/var/lib/docker", "Root of the Docker runtime")
	flag.BoolVar(&config.AutoRestart, []string{"#r", "#-restart"}, true, "--restart on the daemon has been deprecated in favor of --restart policies on docker run")
	flag.BoolVar(&config.EnableIptables, []string{"#iptables", "-iptables"}, true, "Enable addition of iptables rules")
	flag.BoolVar(&config.EnableIpForward, []string{"#ip-forward", "-ip-forward"}, true, "Enable net.ipv4.ip_forward")
	flag.BoolVar(&config.EnableIpMasq, []string{"-ip-masq"}, true, "Enable IP masquerading")
	flag.BoolVar(&config.EnableIPv6, []string{"-ipv6"}, false, "Enable IPv6 networking")
	flag.StringVar(&config.BridgeIP, []string{"#bip", "-bip"}, "", "Specify network bridge IP")
	flag.StringVar(&config.BridgeIface, []string{"b", "-bridge"}, "", "Attach containers to a network bridge")
	flag.StringVar(&config.FixedCIDR, []string{"-fixed-cidr"}, "", "IPv4 subnet for fixed IPs")
	flag.StringVar(&config.FixedCIDRv6, []string{"-fixed-cidr-v6"}, "", "IPv6 subnet for fixed IPs")
	flag.BoolVar(&config.InterContainerCommunication, []string{"#icc", "-icc"}, true, "Enable inter-container communication")
	flag.StringVar(&config.GraphDriver, []string{"s", "-storage-driver"}, "", "Storage driver to use")
	flag.StringVar(&config.ExecDriver, []string{"e", "-exec-driver"}, "native", "Exec driver to use")
	flag.BoolVar(&config.EnableSelinuxSupport, []string{"-selinux-enabled"}, false, "Enable selinux support")
	flag.IntVar(&config.Mtu, []string{"#mtu", "-mtu"}, 0, "Set the containers network MTU")
	flag.StringVar(&config.SocketGroup, []string{"G", "-group"}, "docker", "Group for the unix socket")
	flag.BoolVar(&config.EnableCors, []string{"#api-enable-cors", "-api-enable-cors"}, false, "Enable CORS headers in the remote API")
	flag.StringVar(&config.SeccompConfigPath, []string{"-seccomp-config"}, "", "Enable Seccomp syscall filtering")
	opts.IPVar(&config.DefaultIp, []string{"#ip", "-ip"}, "0.0.0.0", "Default IP when binding container ports")
	opts.ListVar(&config.GraphOptions, []string{"-storage-opt"}, "Set storage driver options")
	// FIXME: why the inconsistency between "hosts" and "sockets"?
	opts.IPListVar(&config.Dns, []string{"#dns", "-dns"}, "DNS server to use")
	opts.DnsSearchListVar(&config.DnsSearch, []string{"-dns-search"}, "DNS search domains to use")
	opts.LabelListVar(&config.Labels, []string{"-label"}, "Set key=value labels to the daemon")
}

func getDefaultNetworkMtu() int {
	if iface, err := networkdriver.GetDefaultRouteIface(); err == nil {
		return iface.MTU
	}
	return defaultNetworkMtu
}

func parseSeccompConfig(path string) (seccomp.SeccompConfig, error) {
	var config seccomp.SeccompConfig

	if path == "" {
		return config, nil
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return config, err
	}


	lines := strings.Split(string(contents), "\n")

	switch strings.ToLower(lines[0]) {
	case "whitelist":
		config.Whitelist = true;
	case "blacklist":
		config.Whitelist = false;
	default:
		return config, fmt.Errorf("Error on line 1 of Seccomp config: Config file must start with WHITELIST or BLACKLIST!")
	}

	// Remove the first line
	lines = lines[1:]

	// Parse each syscall
	for i, line := range lines {
		if len(line) == 0 {
			// Skip empty lines
			continue
		}

		// Do we have arguments?
		if strings.Index(line, "[") != -1 {
			// We have arguments, parse them
			argsStartIndex := strings.Index(line, "[")
			argsEndIndex := strings.Index(line, "]")
			if argsEndIndex == -1 {
				return config, fmt.Errorf("Error on line %d of Seccomp config: Arguments list must be terminated by ]", (i + 2))
			}

			// Get arguments and syscall substrings
			arguments := line[argsStartIndex+1:argsEndIndex]
			syscall := strings.TrimRight(line[0:argsStartIndex], " ")
			if len(syscall) == 0 {
				return config, fmt.Errorf("Error on line %d of Seccomp config: Must provide name of syscall to block!", (i + 2))
			}

			blockedCall := seccomp.BlockedSyscall { Name: syscall }

			// Split the arguments list, which should be semicolon-separated
			argumentsList := strings.Split(arguments, ";")

			for _, arg := range argumentsList {
				// Trim all spaces
				argTrimmed := strings.Replace(arg, " ", "", -1)

				// If the argument is empty, continue
				if len(argTrimmed) == 0 {
					continue
				}

				// Each argument is wrapped in parens
				argNoParens := argTrimmed[1:len(arg)-1]

				// Each will have 3 or 4 comma-separated fields
				fields := strings.Split(argNoParens, ",")
				if len(fields) < 3 || len(fields) > 4 {
					return config, fmt.Errorf("Error on line %d of Seccomp config: Argument restrictions must have an argument number, an operator, and one or two values", (i + 2))
				}

				// Field 1 is the argument number
				argNum, err := strconv.Atoi(fields[0])
				if err != nil {
					return config, fmt.Errorf("Error on line %d of Seccomp config: Could not convert argument number to integer: %s", (i + 2), err)
				} else if argNum < 0 {
					return config, fmt.Errorf("Error on line %d of Seccomp config: Argument number cannot be negative!", (i + 2))
				}

				// Field 3 (and optionally 4) are 64-bit ints
				valOne, err := strconv.ParseInt(fields[2], 0, 64)
				if err != nil {
					return config, fmt.Errorf("Error on line %d of Seccomp config: Could not convert operand 1 to integer: %s", (i + 2), err)
				}

				var valTwo int64
				if len(fields) == 4 {
					valTwo, err = strconv.ParseInt(fields[2], 0, 64)
					if err != nil {
						return config, fmt.Errorf("Error on line %d of Seccomp config: Could not convert operand 2 to integer: %s", (i + 2), err)
					}					
				} else {
					valTwo = 0
				}

				blockedCall.Conditions = append(blockedCall.Conditions, seccomp.SyscallCondition {
					Argument: uint(argNum),
					Operator: fields[1],
					ValueOne: uint64(valOne),
					ValueTwo: uint64(valTwo),
				})
			}

			config.Syscalls = append(config.Syscalls, blockedCall)
		} else {
			// Assume the entire line is a syscall name
			config.Syscalls = append(config.Syscalls, seccomp.BlockedSyscall{ Name: line })
		}
	}

	config.Enable = true

	return config, err
}