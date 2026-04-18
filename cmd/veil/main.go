package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PranavRJoshi/Veil/internal/cli"
	"github.com/PranavRJoshi/Veil/internal/loader"
	ksyscall "github.com/PranavRJoshi/Veil/modules/syscall"
	kfiles "github.com/PranavRJoshi/Veil/modules/files"
)

func main() {

	cfg, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		cli.Usage()
		os.Exit(1)
	}
 
	if cfg.ShowHelp {
		cli.Usage()
		os.Exit(0)
	}
 
	if cfg.ListModules {
		cli.PrintModules()
		os.Exit(0)
	}

	m := loader.NewManager()	

	/*
		done is closed when the user sends SIGINT/SIGTERM. Module
		Run methods select on this channel to know when to exit.
	*/
	done := make(chan struct{})

	/*
		Instantiate and register only the selected module. The
		module's Run method is started as a goroutine after loading.
	*/
	switch cfg.Module {
	case "syscall":
		/* create the filter based on given command line arguments */
		filter, err := ksyscall.ParseFilterConfig(cfg.ModuleFlags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		tracer := ksyscall.New(filter)
		m.Register(tracer)
 
		if err := m.LoadAll(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer m.CloseAll()
 
		go tracer.Run(done)
 
	case "files":
		filter, err := kfiles.ParseFilterConfig(cfg.ModuleFlags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		files := kfiles.New(filter)
		m.Register(files)
 
		if err := m.LoadAll(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer m.CloseAll()
 
		go files.Run(done)
	}

	fmt.Fprintf(os.Stderr, "Veil [%s] running, press ctrl+c to stop\n", cfg.Module)
 
	/*
		Block the process till we are sent the SIGINT or SIGTERM signal.
		Once received, close the done channel to signal goroutines to exit.
	*/
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
 
	close(done)
}
