# Two-stage Dockerfile for ebpf-adblocker.
#
# Stage 1 builds the userspace binary (and runs bpf2go to compile the
# kernel object). Stage 2 is a minimal runtime image. The container
# must be run with --privileged or with CAP_BPF + CAP_NET_ADMIN +
# /sys/fs/bpf mounted in - eBPF can't be sandboxed away.
#
# Build locally:
#   docker build -t ebpf-adblocker:dev .
#
# Run:
#   docker run --rm --privileged --network=host \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     -v "$PWD/configs:/etc/adblocker:ro" \
#     ebpf-adblocker:dev daemon --config /etc/adblocker/adblocker.yaml

# ---------- builder ----------
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev linux-headers-generic \
        linux-tools-generic make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest && \
    go generate ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w \
      -X github.com/ebpf-adblocker/ebpf-adblocker/internal/version.Version=$(git describe --tags --always 2>/dev/null || echo dev) \
      -X github.com/ebpf-adblocker/ebpf-adblocker/internal/version.Commit=$(git rev-parse --short HEAD 2>/dev/null || echo none) \
      -X github.com/ebpf-adblocker/ebpf-adblocker/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -o /out/adblockerctl ./cmd/adblocker

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/adblockerctl /usr/local/bin/adblockerctl
COPY configs/adblocker.yaml /etc/adblocker/adblocker.yaml
COPY configs/allowlist.txt  /etc/adblocker/allowlist.txt
COPY LICENSE                /usr/share/doc/ebpf-adblocker/LICENSE

ENTRYPOINT ["/usr/local/bin/adblockerctl"]
CMD ["daemon", "--config", "/etc/adblocker/adblocker.yaml"]

LABEL org.opencontainers.image.title="ebpf-adblocker" \
      org.opencontainers.image.description="System-wide eBPF ad/tracker blocker" \
      org.opencontainers.image.source="https://github.com/ebpf-adblocker/ebpf-adblocker" \
      org.opencontainers.image.licenses="MIT"
