MODULE_DIR := modules

SYSCALL_MODULE_DIR := $(MODULE_DIR)/syscall
SYSCALL_BPF2GO := $(SYSCALL_MODULE_DIR)/tracer_bpfeb.go $(SYSCALL_MODULE_DIR)/tracer_bpfel.go
SYSCALL_BPF2GO_OBJS := $(SYSCALL_MODULE_DIR)/tracer_bpfeb.o $(SYSCALL_MODULE_DIR)/tracer_bpfel.o

FILES_MODULE_DIR := $(MODULE_DIR)/files
FILES_BPF2GO := $(FILES_MODULE_DIR)/fileaccess_bpfeb.go $(FILES_MODULE_DIR)/fileaccess_bpfel.go
FILES_BPF2GO_OBJS := $(FILES_MODULE_DIR)/fileaccess_bpfeb.o $(FILES_MODULE_DIR)/fileaccess_bpfel.o

.PHONY: all generate clean

all: generate build

generate: bpf/headers/vmlinux.h
	go generate ./...

bpf/headers/vmlinux.h:
	mkdir -p bpf/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

build:
	go build -o bin/veil ./cmd/veil

clean:
	rm -f bin/kernscope bpf/headers/vmlinux.h $(SYSCALL_BPF2GO) \
	$(SYSCALL_BPF2GO_OBJS) $(FILES_BPF2GO) $(FILES_BPF2GO_OBJS)
