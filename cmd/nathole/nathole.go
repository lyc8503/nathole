package main

import (
	"flag"
	"fmt"
	"runtime/debug"

	"github.com/lyc8503/nathole/stun"
	log "github.com/sirupsen/logrus"
)

var (
	logLevel = flag.String("loglevel", "info", "log level [trace, debug, info, warn]")
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

	mappingType, err := stun.MappingTests("stun.miwifi.com:3478")
	log.Infof("%v %v", mappingType, err)
	filteringType, err := stun.FilteringTests("stun.miwifi.com:3478")
	log.Infof("%v %v", filteringType, err)
}
