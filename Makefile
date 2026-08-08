MODULE_DIR := modules

BIN := bin/veil

# Install layout. Completions go to the dirs bash-completion and zsh's compinit
# search by default, so a new shell needs no rc edits. Both shells install
# unconditionally -- each reads only its own dir.
PREFIX      ?= /usr/local
DESTDIR     ?=
BINDIR      := $(DESTDIR)$(PREFIX)/bin
BASHCOMPDIR ?= $(DESTDIR)$(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR  ?= $(DESTDIR)$(PREFIX)/share/zsh/site-functions

HEADER_DIR := bpf/headers
BTF_DIR := bpf/btf

# Kernel release of the vendored BTF blobs, pinned to the oldest kernel Veil
# supports. CO-RE can only reference fields present at compile time, so building
# against 5.8 keeps relocations valid on 5.8+. The floor is 5.8 because every
# module emits through a ring buffer (BPF_MAP_TYPE_RINGBUF, added in 5.8), which
# older BTF lacks. Bumping this raises the baseline.
BTF_RELEASE := 5.8.0-63-generic

VMLINUX_HEADERS := $(HEADER_DIR)/vmlinux_x86.h $(HEADER_DIR)/vmlinux_arm64.h

# bpf2go writes <stem>_<endian>_<arch>.{go,o} per module, one pair per target
# arch. Matched by pattern so adding a module or target needs no edit here.
BPF2GO_ARTIFACTS := $(MODULE_DIR)/*/*_bpfe[lb]*.go $(MODULE_DIR)/*/*_bpfe[lb]*.o

.PHONY: all help generate regenerate build install uninstall clean test test-integration test-integration-race

all: generate build ## Generate BPF objects and build bin/veil

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  %-24s %s\n", $$1, $$2}'

generate: $(VMLINUX_HEADERS) ## Generate vmlinux headers + bpf2go objects (needs clang, bpftool)
	go generate ./...

# bpf2go writes new filenames without removing old ones, so a changed target
# leaves stale objects that collide with the new build constraints. Clean first.
regenerate: ## Clean, then regenerate (after changing a bpf2go target)
	$(MAKE) clean
	$(MAKE) generate

# Headers come from the vendored BTF, not /sys/kernel/btf/vmlinux, so a build
# does not depend on the developer's running kernel and x86 can build on arm64.
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

build: ## Build bin/veil (Go only, no BPF toolchain)
	go build -o $(BIN) ./cmd/veil

install: build ## Install veil + shell completions (PREFIX=/usr/local)
	install -Dm0755 $(BIN) $(BINDIR)/veil
	install -d $(BASHCOMPDIR) $(ZSHCOMPDIR)
	$(BIN) completion bash > $(BASHCOMPDIR)/veil
	$(BIN) completion zsh  > $(ZSHCOMPDIR)/_veil
	@echo "installed $(BINDIR)/veil"

uninstall: ## Remove installed veil + completions
	rm -f $(BINDIR)/veil $(BASHCOMPDIR)/veil $(ZSHCOMPDIR)/_veil

test: ## Run unit tests (race, no root)
	go test -race -count=1 ./...

# Integration tests load real BPF, so the test binary needs root. -exec sudo
# runs only the compiled binary under sudo, leaving the build and module cache
# owned by the current user.
test-integration: ## Run integration tests (loads BPF, needs sudo)
	go test -tags integration -exec sudo -count=1 -timeout 5m ./modules/...

# Separate from test-integration: -race slows Go execution, and the negative
# assertions are fixed wall-clock windows, so "no event arrived" gets easier to
# satisfy under it. The non-race run stays authoritative; this pass exists to
# catch data races in the modules and harness.
test-integration-race: ## Integration tests under the race detector
	go test -tags integration -exec sudo -count=1 -race -timeout 10m ./modules/...

clean: ## Remove generated files and the binary
	rm -f $(BIN)
	rm -f $(VMLINUX_HEADERS) $(HEADER_DIR)/vmlinux.h $(HEADER_DIR)/.btf_*.tmp
	rm -f $(BPF2GO_ARTIFACTS)
