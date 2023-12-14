package main

import (
	"flag"
	"fmt"

	"github.com/lyc8503/nathole/stun"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)


func main() {
	fmt.Println("nathole version unknown")

	// parse cmdline flags
	logLevel := zap.LevelFlag("loglevel", zapcore.InfoLevel, "set log level")
	flag.Parse()

	// setup global logger
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.Level = zap.NewAtomicLevelAt(*logLevel)
	devLogger, _ := config.Build()
	defer devLogger.Sync()
	zap.ReplaceGlobals(devLogger)
	

	stun.Start()

}