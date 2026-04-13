.PHONY: all generate clean

all: generate build

generate: bpf/headers/vmlinux.h
	go generate ./...

bpf/headers/vmlinux.h:
	mkdir -p bpf/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

build:
	go build -o bin/kernscope ./cmd/kernscope

clean:
	rm -f bin/kernscope modules/syscall/tracer_bpfel.go \
	modules/syscall/tracer_bpfeb.go modules/syscall/tracer_bpfel.o \
	modules/syscall/tracer_bpfeb.o modules/syscall/syscall_table.go \
	bpf/headers/vmlinux.h
