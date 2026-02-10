# Process Creation Comparison: fork() vs vfork() vs posix_spawn()

**ECS 251 - Operating Systems Project**

A systematic evaluation of Linux process creation mechanisms under varying memory footprints and page configurations.

## Team Members
- Abhijeet Rastogi
- Haochen Dong
- Mahima Rudrapati

## Project Overview

Process creation is fundamental to modern operating systems, but the traditional `fork()` system call incurs significant overhead when the parent process holds large memory footprints. This project benchmarks three process creation mechanisms—`fork()`, `vfork()`, and `posix_spawn()`—under controlled memory conditions to quantify their performance characteristics.

### Research Questions
- How does parent process memory size affect process creation latency?
- What is the impact of Transparent Huge Pages (2MB vs 4KB) on fork overhead?
- How do `vfork()` and `posix_spawn()` compare to traditional `fork()` in memory-intensive scenarios?

## System Requirements

### Hardware
- Multi-core x86-64 CPU (minimum 8 cores recommended)
- Minimum 32 GB RAM
- Tested on AWS EC2 c5.4xlarge (16 vCPUs, 32 GB RAM)

### Software
- Ubuntu 22.04 LTS or similar Linux distribution
- Linux kernel 5.15+ (6.x recommended)
- GCC compiler with C11 support
- Root/sudo access for system configuration

## Repository Structure
```
.
├── benchmark.c          # Main benchmarking suite
├── quick_test.c         # System verification tests
├── Makefile            # Build and setup automation
└── README.md           # This file
```

### File Descriptions

**`benchmark.c`**
- Complete benchmarking framework with high-resolution timing
- Tests memory sizes: 1GB, 2GB (configurable in `MEMORY_SIZES` array)
- Tests both 4KB regular pages and 2MB transparent huge pages
- Implements all three process creation methods
- Outputs detailed CSV results with mean, stddev, and 99th percentile latencies
- 100 iterations per configuration for statistical significance

**`quick_test.c`**
- Lightweight validation suite (100MB memory footprint)
- Verifies system calls work correctly
- Tests memory allocation with `mmap()` and `madvise()`
- Validates high-resolution timer functionality
- Useful for debugging setup issues before running full benchmarks

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/AbhijeetRastogi/ECS251_process_creation_comparison.git
cd ECS251_process_creation_comparison
```

### 2. Build the Project
```bash
make all
```

This creates two executables:
- `benchmark` - Main benchmarking program
- `quick_test` - System verification tool

### 3. System Configuration (Requires Root)

Check current system configuration:
```bash
make check-hugepages
```

Configure system for optimal benchmarking:
```bash
make setup
```

This will:
- Enable transparent huge pages
- Disable swap (prevents interference)
- Set CPU governor to performance mode

**Manual Setup (Alternative):**
```bash
# Enable THP
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

# Disable swap
sudo swapoff -a

# Set CPU governor (if available)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Usage

### Quick Verification Test
Before running the full benchmark, verify your system setup:
```bash
make test
```

Expected output:
- Successful fork(), vfork(), and posix_spawn() tests
- Memory allocation and page touching verification
- THP configuration status
- Timer resolution confirmation (~1 nanosecond)

### Run Full Benchmark
```bash
make run
```

Or manually:
```bash
./benchmark
```

The benchmark will:
1. Test each memory size (1GB, 2GB)
2. Test both page types (4KB regular, 2MB huge)
3. Test all three methods (fork, vfork, posix_spawn)
4. Run 100 iterations per configuration
5. Output results to console and `benchmark_results.txt`

**Expected runtime:** 10-30 minutes depending on system

### View Results

Results are printed in CSV format:
```
Memory_GB,Page_Size,Method,Mean_ms,StdDev_ms,P99_ms,Min_ms,Max_ms
1,4KB,fork,12.345,1.234,15.678,10.123,18.901
1,4KB,vfork,0.123,0.012,0.156,0.098,0.189
...
```

## Configuration

### Modify Memory Sizes
Edit `benchmark.c`:
```c
// Line ~20
static const size_t MEMORY_SIZES[] = {1, 2, 4, 8, 16};  // Add more sizes
```

### Adjust Iterations
Edit `benchmark.c`:
```c
// Line ~18
#define NUM_ITERATIONS 100  // Increase for more statistical confidence
```

### Change Page Sizes
Edit `benchmark.c`:
```c
// Lines ~16-17
#define PAGE_SIZE_4KB (4 * 1024)
#define PAGE_SIZE_2MB (2 * 1024 * 1024)
```

## Expected Results

Based on our research hypothesis:

| Method | Latency (1GB) | Latency (16GB) | Memory Scaling |
|--------|---------------|----------------|----------------|
| `fork()` | ~10-20 ms | ~150-300 ms | Linear with memory |
| `vfork()` | <1 ms | <1 ms | Constant |
| `posix_spawn()` | <1 ms | <1 ms | Constant |

**Transparent Huge Pages Impact:**
- Expected 10-30% reduction in fork() latency
- Minimal impact on vfork() and posix_spawn()

## Troubleshooting

### Permission Denied Errors
```bash
sudo ./benchmark  # Run with elevated privileges
```

### Insufficient Memory
Reduce memory sizes in `MEMORY_SIZES` array or free up system memory

### THP Not Available
Check kernel support:
```bash
cat /sys/kernel/mm/transparent_hugepage/enabled
```

If not available, benchmark will still run with 4KB pages only

### Compilation Errors
Ensure you have required libraries:
```bash
sudo apt-get update
sudo apt-get install build-essential
```

## Clean Up

Remove build artifacts and results:
```bash
make clean
```

Re-enable swap after benchmarking:
```bash
sudo swapon -a
```

## Next Week's Work

- Add eBPF-based kernel tracing for page faults and TLB shootdowns
- Integrate `perf` hardware counter collection
- Test with up to 16GB memory configurations
- Add automated plotting scripts for result visualization

---

**Last Updated:** February 2026