package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PranavRJoshi/go-kernscope/internal/loader"
	ksyscall "github.com/PranavRJoshi/go-kernscope/modules/syscall"
)

func main() {
	tracer := ksyscall.New()

	m := loader.NewManager()
	m.Register(tracer)

	if err := m.LoadAll(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer m.CloseAll()

	fmt.Println("kscope running, press ctrl+c to stop")

	/*
		A simple goroutine which traces the events that has occurred and
		prints it to the standard output.
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
		Block the process till we are sent the SIGINT signal.
	*/
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
