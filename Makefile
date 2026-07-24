MODULE_DIR := modules

BIN := bin/veil

HEADER_DIR := bpf/headers
BTF_DIR := bpf/btf

# Kernel release the vendored BTF blobs come from. Pinned to the oldest
# kernel Veil supports: CO-RE can only reference fields present at compile
# time, so building against 5.8 guarantees the relocations resolve on
# anything from 5.8 upwards. Bumping this is a deliberate decision to raise
# the baseline, not a routine update.
#
# 5.8 is the floor because every module emits through a ring buffer, and
# BPF_MAP_TYPE_RINGBUF landed in 5.8. A 5.4 BTF does not define it, nor
# BPF_ANY, so the sources do not compile against one.
BTF_RELEASE := 5.8.0-63-generic

VMLINUX_HEADERS := $(HEADER_DIR)/vmlinux_x86.h $(HEADER_DIR)/vmlinux_arm64.h

# bpf2go writes <stem>_<endian>_<arch>.{go,o} into each module directory,
# one pair per target architecture. Matched by pattern so adding a module
# or a target does not mean editing this file.
BPF2GO_ARTIFACTS := $(MODULE_DIR)/*/*_bpfe[lb]*.go $(MODULE_DIR)/*/*_bpfe[lb]*.o

.PHONY: all generate regenerate build clean test test-integration

all: generate build

generate: $(VMLINUX_HEADERS)
	go generate ./...

# Regenerate from scratch. Needed after changing a bpf2go target, since
# bpf2go writes new filenames without removing the old ones, and stale
# objects would collide with the new build constraints.
regenerate:
	$(MAKE) clean
	$(MAKE) generate

# The headers are derived from the vendored BTF rather than from
# /sys/kernel/btf/vmlinux, so a build does not depend on whichever kernel
# the developer happens to be running, and the x86 target can be built on
# an arm64 host.
$(HEADER_DIR)/vmlinux_x86.h: $(BTF_DIR)/x86_64/$(BTF_RELEASE).btf.tar.xz
	@mkdir -p $(HEADER_DIR)
	tar -xOf $< > $(HEADER_DIR)/.btf_x86.tmp
	bpftool btf dump file $(HEADER_DIR)/.btf_x86.tmp format c > $@
	@rm -f $(HEADER_DIR)/.btf_x86.tmp

$(HEADER_DIR)/vmlinux_arm64.h: $(BTF_DIR)/arm64/$(BTF_RELEASE).btf.tar.xz
	@mkdir -p $(HEADER_DIR)
	tar -xOf $< > $(HEADER_DIR)/.btf_arm64.tmp
	bpftool btf dump file $(HEADER_DIR)/.btf_arm64.tmp format c > $@
	@rm -f $(HEADER_DIR)/.btf_arm64.tmp

build:
	go build -o $(BIN) ./cmd/veil

test:
	go test -race ./...

# Integration tests load real BPF programs, so the test binary needs root.
# -exec sudo runs only the compiled binary under sudo, keeping the build
# and the module cache owned by the current user.
test-integration:
	go test -tags integration -exec sudo -count=1 -timeout 5m ./modules/...

# Separate from test-integration rather than folded into it. The race
# detector slows Go-side execution, and the negative assertions are fixed
# wall-clock windows, so under -race "no event arrived" becomes easier to
# satisfy. The non-race run stays the authoritative one; this pass exists
# to find data races in the modules and the test harness.
test-integration-race:
	go test -tags integration -exec sudo -count=1 -race -timeout 10m ./modules/...

clean:
	rm -f $(BIN)
	rm -f $(VMLINUX_HEADERS) $(HEADER_DIR)/vmlinux.h $(HEADER_DIR)/.btf_*.tmp
	rm -f $(BPF2GO_ARTIFACTS)
