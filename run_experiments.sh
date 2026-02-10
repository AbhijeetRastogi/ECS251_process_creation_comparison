#!/bin/bash

set -e

echo "=========================================="
echo "Running Process Creation Benchmarks"
echo "=========================================="

# Configuration
OUTPUT_DIR="results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "Results will be saved to: $OUTPUT_DIR"

# Check if benchmark is built
if [ ! -f ./benchmark ]; then
    echo "Benchmark not found. Building..."
    make
fi

# System information
echo ""
echo "Collecting system information..."
{
    echo "=== System Information ==="
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo ""
    echo "=== CPU Info ==="
    lscpu
    echo ""
    echo "=== Memory Info ==="
    free -h
    echo ""
    echo "=== Huge Pages Status ==="
    cat /sys/kernel/mm/transparent_hugepage/enabled
    cat /proc/meminfo | grep -i huge
    echo ""
    echo "=== CPU Governor ==="
    cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | head -1 || echo "Not available"
} > "$OUTPUT_DIR/system_info.txt"

# Run benchmark without perf first for baseline
echo ""
echo "Running baseline benchmark..."
./benchmark | tee "$OUTPUT_DIR/baseline_results.txt"

# Extract CSV data
echo ""
echo "Extracting CSV data..."
grep -A 100 "Memory_GB,Page_Size" "$OUTPUT_DIR/baseline_results.txt" > "$OUTPUT_DIR/results.csv" || true

# Run with perf stat for hardware counters
echo ""
echo "Running benchmark with perf stat..."
sudo perf stat -e \
    cycles,instructions,cache-references,cache-misses,\
    page-faults,minor-faults,major-faults,\
    dTLB-loads,dTLB-load-misses,iTLB-loads,iTLB-load-misses \
    -o "$OUTPUT_DIR/perf_stat.txt" \
    ./benchmark > "$OUTPUT_DIR/perf_results.txt" 2>&1 || true

echo ""
echo "Checking if eBPF tracing is available..."
if command -v bpftrace &> /dev/null; then
    echo "✓ bpftrace is available"
    echo "  Note: eBPF tracing will be added in Week 2"
else
    echo "✗ bpftrace not found. Install with: sudo apt-get install bpftrace"
fi

# Create summary
echo ""
echo "Creating summary..."
{
    echo "=== Benchmark Summary ==="
    echo "Date: $(date)"
    echo ""
    echo "=== Quick Results ==="
    echo ""
    
    if [ -f "$OUTPUT_DIR/results.csv" ]; then
        echo "Results by method (Mean latency in ms):"
        echo ""
        # Parse CSV and show summary by method
        awk -F, 'NR>1 {method=$3; if(!seen[method]++) print "Method: " method} NR>1 {print "  " $1 "GB (" $2 "): " $4 " ms"}' "$OUTPUT_DIR/results.csv"
    fi
    
    echo ""
    echo "=== Key Findings ==="
    echo "1. Check fork() scaling with memory size in results.csv"
    echo "2. Compare 4KB vs 2MB page performance"
    echo "3. Verify vfork/posix_spawn constant latency"
    echo ""
    echo "Full results available in: $OUTPUT_DIR/"
    
} | tee "$OUTPUT_DIR/summary.txt"

echo ""
echo "=========================================="
echo "Benchmark Complete!"
echo "=========================================="
echo ""
echo "Results saved to: $OUTPUT_DIR/"
echo ""
echo "Key files:"
echo "  - results.csv          : Main benchmark results"
echo "  - baseline_results.txt : Full benchmark output"
echo "  - perf_stat.txt        : Hardware performance counters"
echo "  - system_info.txt      : System configuration"
echo "  - summary.txt          : Quick summary"
