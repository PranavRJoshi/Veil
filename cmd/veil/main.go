package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PranavRJoshi/Veil/internal/loader"
	ksyscall "github.com/PranavRJoshi/Veil/modules/syscall"
	kfiles "github.com/PranavRJoshi/Veil/modules/files"
)

func main() {
	tracer := ksyscall.New()
	files := kfiles.New()

	m := loader.NewManager()
	m.Register(tracer)
	m.Register(files)

	if err := m.LoadAll(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer m.CloseAll()

	fmt.Println("Veil running, press ctrl+c to stop")

	/*
		Goroutine whose task is to collect the syscall events
		and print them out
	*/
	go func() {
		for e := range tracer.Events {
			fmt.Printf("[%s] pid=%-6d comm=%s syscall=%s\n",
				e.Kind,
				e.PID,
				e.ProcessName(),
				ksyscall.SyscallName(e.SyscallNr),
			)
		}
	}()

	/*
		Goroutine whose task is to collect the file access events
		and print them out
	*/
	go func() {
		for e := range files.Events {
			fmt.Printf("[%s] pid=%-6d comm=%-16s op=%-6s path=%s\n",
				e.Kind,
				e.PID,
				e.ProcessName(),
				e.Op,
				e.Path,
			)
		}
	}()

	/*
		Block the process till we are sent the SIGINT signal.
	*/
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
