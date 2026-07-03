# Use a stable Ubuntu base with modern LLVM/Clang toolchains
FROM ubuntu:24.04 AS builder

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install compilation toolchain and eBPF development dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    make \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Establish the workspace
WORKDIR /build

# ---------------------------------------------------------------------------
# Self-contained build stage: compiles the object into the image itself.
# For host-local builds via a bind mount, use the "builder" stage + Makefile.
# ---------------------------------------------------------------------------
FROM builder AS compiled

# Copy the eBPF source code into the container
# (Assumes ebpf-tunnel-clamp-mss.c is in your current directory)
COPY ebpf-tunnel-clamp-mss.c .

# Compile the source into the target BPF object binary
# Using -O2 is mandatory for the BPF verifier to unroll loops properly
RUN clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c ebpf-tunnel-clamp-mss.c \
    -o ebpf-tunnel-clamp-mss.o

# Default command just outputs a verification of the built binary
CMD ["llvm-objdump", "-h", "ebpf-tunnel-clamp-mss.o"]