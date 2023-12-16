package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"github.com/lyc8503/nathole/stun"
	log "github.com/sirupsen/logrus"
)

var (
	logLevel   = flag.String("loglevel", "info", "log level [trace, debug, info, warn]")
	stunServer = flag.String("stun-server", "stunserver.stunprotocol.org:3478", "STUN server address and port, for basic functionality of this program, the STUN server MUST support NAT discovery.\nif you want to use the IPv4 TCP hole punching feature, the STUN server should also support TCP.\nif you want to use the IPv6 hole punching feature, the STUN server should also support IPv6.")
)

func printVersion() {
	if info, ok := debug.ReadBuildInfo(); ok {
		var revision string
		var modified bool

		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value[:7]
			}
			if setting.Key == "vcs.modified" {
				modified = setting.Value == "true"
			}
		}

		if revision != "" {
			if modified {
				revision += " (modified)"
			}
			fmt.Printf("nathole version devel %s\n", revision)
		} else {
			fmt.Println("nathole version unknown")
			fmt.Printf("%+v", info)
		}
	} else {
		fmt.Println("nathole version unknown")
	}
}

func main() {
	printVersion()

	flag.Parse()
	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("parse log level failed: %v", err)
	}
	log.SetLevel(level)
	if level == log.DebugLevel || level == log.TraceLevel {
		// Enable function name and line number reporting at debug or trace level
		log.SetReportCaller(true)
		log.SetFormatter(&log.TextFormatter{
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := f.File[strings.LastIndex(f.File, string(os.PathSeparator))+1:]
				caller := strings.Replace(fmt.Sprintf("%s:%d", filename, f.Line), ".go", "", 1)
				return "", "[" + caller + strings.Repeat(" ", max(12-utf8.RuneCountInString(caller), 0)) + "]"
			},
		})
	}

	log.Info("=> Testing NAT Type for local network...")
	log.Info("===== IPv4 Tests =====")

	mappingType, err := stun.MappingTests(*stunServer, "udp4")
	if err != nil {
		log.Errorf("NAT mapping test failed: %+v", err)
	}
	log.Infof("NATMappingBehavior: %s", mappingType.String())
	filteringType, err := stun.FilteringTests(*stunServer, "udp4")
	if err != nil {
		log.Errorf("NAT filtering test failed: %+v", err)
	}
	log.Infof("NATFilteringBehavior: %s", filteringType.String())

	if mappingType == stun.NoNAT {
		if filteringType == stun.EndpointIndependentFiltering {
			log.Info("=> No NAT and firewall detected")
		} else {
			log.Info("=> No NAT detected, firewall detected")
		}
	} else {
		if mappingType == stun.EndpointIndependentMapping && filteringType == stun.EndpointIndependentFiltering {
			log.Info("=> Full Cone NAT detected (NAT A)")
		} else if mappingType == stun.EndpointIndependentMapping && filteringType == stun.AddressDependentFiltering {
			log.Info("=> Address Restricted Cone NAT detected (NAT B)")
		} else if mappingType == stun.EndpointIndependentMapping && filteringType == stun.AddressAndPortDependentFiltering {
			log.Info("=> Port Restricted Cone NAT detected (NAT C)")
		} else if mappingType != stun.EndpointIndependentMapping && filteringType == stun.AddressAndPortDependentFiltering {
			log.Info("=> Symmetric NAT detected (NAT D)")
		} else {
			log.Error("=> Unknown NAT type, please check your stun server setting and network environment")
			log.Error("=> Report this to https://github.com/lyc8503/nathole/issues if you consider this a bug")
		}
	}

	log.Info("===== IPv6 Tests =====")

	mappingType, err = stun.MappingTests(*stunServer, "udp6")
	if err != nil {
		log.Errorf("NAT mapping test failed: %+v", err)
	}
	log.Infof("NATMappingBehavior: %s", mappingType.String())
	filteringType, err = stun.FilteringTests(*stunServer, "udp6")
	if err != nil {
		log.Errorf("NAT filtering test failed: %+v", err)
	}
	log.Infof("NATFilteringBehavior: %s", filteringType.String())

	if mappingType == stun.NoNAT {
		if filteringType == stun.EndpointIndependentFiltering {
			log.Info("=> No NAT and firewall detected")
		} else {
			log.Info("=> No NAT detected, firewall detected")
		}
	} else {
		if mappingType == stun.EndpointIndependentMapping && filteringType == stun.EndpointIndependentFiltering {
			log.Info("=> Full Cone NAT detected (NAT A)")
		} else if mappingType == stun.EndpointIndependentMapping && filteringType == stun.AddressDependentFiltering {
			log.Info("=> Address Restricted Cone NAT detected (NAT B)")
		} else if mappingType == stun.EndpointIndependentMapping && filteringType == stun.AddressAndPortDependentFiltering {
			log.Info("=> Port Restricted Cone NAT detected (NAT C)")
		} else if mappingType != stun.EndpointIndependentMapping && filteringType == stun.AddressAndPortDependentFiltering {
			log.Info("=> Symmetric NAT detected (NAT D)")
		} else {
			log.Error("=> Unknown NAT type, please check your stun server setting and network environment")
			log.Error("=> Report this to https://github.com/lyc8503/nathole/issues if you consider this a bug")
		}
	}

	localAddr, mappedAddr, err := stun.GetTCP4MappedAddress(*stunServer)
	if err != nil {
		log.Fatalf("get mapped address failed: %+v", err)
	}
	log.Infof("local: %s, mapped: %s", localAddr, mappedAddr)
}
