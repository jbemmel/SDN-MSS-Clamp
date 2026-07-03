# Makefile for the TCP MSS clamp eBPF program and its FRR runtime image.
#
# Targets:
#   runtime (default) - build the deployable FRR image with the eBPF clamp baked
#                       in (Dockerfile.frr). This is the image the netlab
#                       topology.yml consumes as `frr-mss-clamp:latest`.
#   build             - compile just the eBPF object on the host via a bind mount
#   clean             - remove the compiled object

IMAGE          := ebpf-mss-clamp-builder
RUNTIME_IMAGE  := frr-mss-clamp:latest
FRR_DOCKERFILE := Dockerfile.frr
SRC            := ebpf-tunnel-clamp-mss.c
OBJ            := $(SRC:.c=.o)

# BPF compilation flags (kept in sync with the Dockerfile)
CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu

# Run the container as the invoking user so the output file is not root-owned
DOCKER_RUN  := docker run --rm \
	-v $(CURDIR):/build -w /build \
	-u $(shell id -u):$(shell id -g) \
	$(IMAGE)

.PHONY: all runtime build builder-image clean

all: runtime

## runtime: build the FRR runtime image with the eBPF clamp baked in
runtime: $(FRR_DOCKERFILE) $(SRC)
	docker build -f $(FRR_DOCKERFILE) -t $(RUNTIME_IMAGE) .

## build: compile $(SRC) into $(OBJ) on the host via a bind mount
build: $(OBJ)

$(OBJ): $(SRC) | builder-image
	$(DOCKER_RUN) clang $(CLANG_FLAGS) -c $(SRC) -o $(OBJ)
	$(DOCKER_RUN) llvm-objdump -h $(OBJ)

## builder-image: build the toolchain-only image used for host-local builds
builder-image:
	docker build --target builder -t $(IMAGE) .

## clean: remove the compiled object
clean:
	rm -f $(OBJ)
