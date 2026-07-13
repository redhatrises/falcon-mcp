# Build stage — Red Hat Hardened Images Go toolchain embeds the validated
# FIPS module in all binaries automatically.
FROM registry.access.redhat.com/hi/go:1.26-fips AS builder

WORKDIR /src

# Version metadata stamped into the binary via ldflags.
ARG VERSION=0.0.0+dev
ARG COMMIT=unknown

# Download modules first so the layer is cached when only source changes.
COPY go.mod go.sum ./
RUN go mod download

# Build the static binary. CGO_ENABLED=0 matches .goreleaser.yaml so the
# runtime stage needs no C libraries.
COPY . .
RUN CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/crowdstrike/falcon-mcp/internal/version.Version=${VERSION} \
            -X github.com/crowdstrike/falcon-mcp/internal/version.Commit=${COMMIT}" \
        -o /tmp/falcon-mcp \
        ./cmd/falcon-mcp/main.go

# Runtime stage — minimal hardened base; GODEBUG runs the binary in FIPS mode.
FROM registry.access.redhat.com/hi/core-runtime:latest

LABEL io.modelcontextprotocol.server.name="io.github.CrowdStrike/falcon-mcp"

COPY --from=builder /tmp/falcon-mcp /falcon-mcp

# FIPS mode is off by default (GODEBUG empty). The validated FIPS module is
# compiled into the binary regardless, so enabling it is a pure runtime toggle:
# docker run -e GODEBUG=fips140=on ... (values: on, only).
ENV GODEBUG=

# Run as a non-root user (UID matches OpenShift arbitrary-UID conventions).
USER 1001

ENTRYPOINT ["/falcon-mcp"]
