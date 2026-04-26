# ebpf-adblocker Makefile
#
# Targets:
#   make            - generate + build
#   make generate   - run go generate (invokes bpf2go -> clang)
#   make build      - build the userspace binary `adblockerctl`
#   make vmlinux    - regenerate bpf/vmlinux.h from running kernel BTF
#   make test       - go test ./...
#   make fmt        - go fmt ./...
#   make deps       - install bpf2go
#   make install    - install binary, configs, and systemd unit
#   make clean      - remove build artifacts
#   make help       - this help

GO              ?= go
CLANG           ?= clang
BPFTOOL         ?= bpftool
BIN             ?= adblockerctl
PREFIX          ?= /usr/local
INSTALL_BIN     ?= $(PREFIX)/bin
INSTALL_ETC     ?= /etc/adblocker
INSTALL_UNIT    ?= /etc/systemd/system

.PHONY: all
all: generate build

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/adblocker

.PHONY: vmlinux
vmlinux:
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "bpftool not found. Install: apt install linux-tools-common linux-tools-generic   |   dnf install bpftool   |   pacman -S bpf"; exit 1; }
	@test -r /sys/kernel/btf/vmlinux || { echo "/sys/kernel/btf/vmlinux missing. Need a CONFIG_DEBUG_INFO_BTF=y kernel."; exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@echo "wrote bpf/vmlinux.h"

.PHONY: test
test:
	$(GO) test ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: deps
deps:
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

.PHONY: install
install: build
	install -D -m 0755 $(BIN) $(DESTDIR)$(INSTALL_BIN)/$(BIN)
	install -D -m 0644 configs/adblocker.yaml $(DESTDIR)$(INSTALL_ETC)/adblocker.yaml
	install -D -m 0644 configs/allowlist.txt  $(DESTDIR)$(INSTALL_ETC)/allowlist.txt
	install -D -m 0644 systemd/adblocker.service $(DESTDIR)$(INSTALL_UNIT)/adblocker.service
	@echo "Installed. Run: systemctl daemon-reload && systemctl enable --now adblocker"

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -f internal/loader/adblocker_bpf*.go internal/loader/adblocker_bpf*.o

.PHONY: help
help:
	@grep -E '^\.PHONY: ' Makefile | awk '{print "  "$$2}' | sort -u
