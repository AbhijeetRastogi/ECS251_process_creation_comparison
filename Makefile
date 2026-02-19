# =============================================================================
# Makefile for benchmark + eBPF tracer
#
# BUILD REQUIREMENTS:
#   - clang (for compiling BPF kernel program)
#   - libbpf-dev  (apt install libbpf-dev)
#   - linux-headers-$(uname -r)  (for BPF kernel headers)
#   - bpftool  (for checking system, optional)
#   - libelf-dev, zlib1g-dev  (libbpf dependencies)
#
# USAGE:
#   make              - build everything
#   make check-ebpf   - check if eBPF is available on this system
#   make check-hugepages - check huge page configuration
#   make setup        - configure system for benchmarking (requires root)
#   make run          - build and run the benchmark (requires root for eBPF)
#   make clean        - remove all build artifacts
# =============================================================================

CC      = gcc
CLANG   = clang

# Detect kernel architecture for BPF includes
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compiler flags for userspace code
CFLAGS  = -O2 -Wall -Wextra -g
CFLAGS += -I/usr/include/x86_64-linux-gnu   # may need adjustment per distro

# Linker flags for userspace: link against libbpf, libelf (ELF parser), 
# libz (compression), libm (math functions used in statistics)
LDFLAGS = -lbpf -lelf -lz -lm

# BPF compiler flags (compiling for the BPF virtual machine, not the host CPU)
BPF_CFLAGS  = -g -O2
BPF_CFLAGS += -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I/usr/include/x86_64-linux-gnu
BPF_CFLAGS += -I/usr/include

# Build targets
BENCHMARK  = benchmark
BPF_OBJ    = tracer.bpf.o
USERSPACE_OBJS = benchmark.o ebpf_tracer.o

# =============================================================================
# Main build targets
# =============================================================================

.PHONY: all clean run check-ebpf check-hugepages setup help

all: $(BPF_OBJ) $(BENCHMARK)

#
# Step 1: Compile the BPF kernel program
#
# This compiles tracer.bpf.c to BPF bytecode (not x86/ARM machine code).
# The output tracer.bpf.o is loaded at runtime by the benchmark using libbpf.
#
# -g              : include BTF (BPF Type Format) debug info
#                   BTF allows the BPF verifier and tools to understand
#                   data types inside the BPF program at runtime
# -target bpf     : compile for the BPF virtual machine instruction set,
#                   not the host CPU
# -D__TARGET_ARCH : tells BPF headers which CPU architecture we're on
#
$(BPF_OBJ): tracer.bpf.c tracer.h
	@echo ">>> Compiling BPF kernel program: $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo ">>> BPF object built: $@"

#
# Step 2: Compile userspace source files
#
benchmark.o: benchmark.c tracer.h ebpf_tracer.h
	@echo ">>> Compiling userspace: $<"
	$(CC) $(CFLAGS) -c $< -o $@

ebpf_tracer.o: ebpf_tracer.c ebpf_tracer.h tracer.h
	@echo ">>> Compiling eBPF loader: $<"
	$(CC) $(CFLAGS) -c $< -o $@

#
# Step 3: Link everything into the final benchmark binary
#
$(BENCHMARK): $(USERSPACE_OBJS)
	@echo ">>> Linking benchmark binary"
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo ">>> Build complete: ./$(BENCHMARK)"
	@echo ""
	@echo "    Run with: sudo ./$(BENCHMARK)"
	@echo "    (root required for eBPF kernel tracing)"

# =============================================================================
# Run the benchmark (needs root for eBPF)
# =============================================================================

run: all
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo ">>> Re-running with sudo (eBPF requires root)..."; \
		sudo ./$(BENCHMARK); \
	else \
		./$(BENCHMARK); \
	fi

# =============================================================================
# System checks
# =============================================================================

check-ebpf:
	@echo "=== eBPF System Check ==="
	@echo ""
	@echo "--- Kernel version ---"
	@uname -r
	@echo ""
	@echo "--- BPF support ---"
	@if [ -f /proc/sys/kernel/bpf_stats_enabled ]; then \
		echo "BPF stats: enabled"; \
	else \
		echo "BPF stats: not available (kernel may be too old)"; \
	fi
	@echo ""
	@echo "--- Required tracepoints ---"
	@for tp in \
		/sys/kernel/debug/tracing/events/exceptions/page_fault_user \
		/sys/kernel/debug/tracing/events/exceptions/page_fault_kernel \
		/sys/kernel/debug/tracing/events/tlb/tlb_flush; do \
		if [ -d "$$tp" ]; then \
			echo "  [OK] $$tp"; \
		else \
			echo "  [MISSING] $$tp  <-- eBPF tracing will fail!"; \
		fi; \
	done
	@echo ""
	@echo "--- Required tools ---"
	@which clang   && echo "  [OK] clang"   || echo "  [MISSING] clang  (apt install clang)"
	@which bpftool && echo "  [OK] bpftool" || echo "  [MISSING] bpftool (apt install linux-tools-common)"
	@echo ""
	@echo "--- libbpf ---"
	@if pkg-config --exists libbpf 2>/dev/null; then \
		echo "  [OK] libbpf $$(pkg-config --modversion libbpf)"; \
	else \
		echo "  [MISSING] libbpf  (apt install libbpf-dev)"; \
	fi
	@echo ""
	@echo "--- Privileges ---"
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo "  [OK] Running as root"; \
	else \
		echo "  [INFO] Not root - eBPF tracing requires root or CAP_BPF"; \
	fi

check-hugepages:
	@echo "=== Huge Pages Configuration ==="
	@echo ""
	@echo "--- Transparent Huge Pages status ---"
	@cat /sys/kernel/mm/transparent_hugepage/enabled
	@echo ""
	@echo "--- Huge page sizes available ---"
	@ls /sys/kernel/mm/hugepages/
	@echo ""
	@echo "--- Current huge page counts ---"
	@grep -i huge /proc/meminfo

# =============================================================================
# System setup (requires root)
# =============================================================================

setup:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo ">>> Error: 'make setup' requires root. Run: sudo make setup"; \
		exit 1; \
	fi
	@echo "=== Configuring system for benchmarking ==="
	@echo ""
	@echo "--- Enabling Transparent Huge Pages ---"
	echo always > /sys/kernel/mm/transparent_hugepage/enabled
	@echo "  THP: $$(cat /sys/kernel/mm/transparent_hugepage/enabled)"
	@echo ""
	@echo "--- Disabling swap (prevents slow disk I/O skewing results) ---"
	swapoff -a || echo "  (swapoff failed or no swap configured)"
	@echo ""
	@echo "--- Setting CPU governor to performance mode ---"
	@for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do \
		if [ -f "$$cpu" ]; then \
			echo performance > "$$cpu"; \
		fi; \
	done
	@echo "  CPU governor: $$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')"
	@echo ""
	@echo "--- Disabling CPU frequency scaling (for consistent timing) ---"
	@for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq; do \
		if [ -f "$$cpu" ]; then \
			max=$$(cat $$(dirname $$cpu)/cpuinfo_max_freq 2>/dev/null); \
			if [ -n "$$max" ]; then echo $$max > $$cpu; fi; \
		fi; \
	done
	@echo ""
	@echo "=== Setup complete. System ready for benchmarking. ==="

# =============================================================================
# Cleanup
# =============================================================================

clean:
	@echo ">>> Cleaning build artifacts"
	rm -f $(BENCHMARK) $(BPF_OBJ) $(USERSPACE_OBJS)
	@echo ">>> Clean done"

# =============================================================================
# Help
# =============================================================================

help:
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Build BPF program and benchmark binary"
	@echo "  make run          - Build and run (auto-elevates to root)"
	@echo "  make check-ebpf   - Check eBPF prerequisites on this system"
	@echo "  make check-hugepages - Check huge page configuration"
	@echo "  make setup        - Configure system for clean benchmarking (root)"
	@echo "  make clean        - Remove all build artifacts"
	@echo ""
	@echo "Build requirements:"
	@echo "  apt install clang libbpf-dev libelf-dev linux-headers-\$$(uname -r)"
	@echo ""
	@echo "Run requirements:"
	@echo "  sudo ./benchmark  (root needed for eBPF kernel tracing)"
	@echo ""