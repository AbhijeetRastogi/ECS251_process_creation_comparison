#!/bin/bash

set -e

echo "=========================================="
echo "AWS Instance Setup for Process Creation Benchmark"
echo "=========================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Please run as normal user (script will use sudo when needed)"
    exit 1
fi

# Update system
echo ""
echo "Step 1: Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install required packages
echo ""
echo "Step 2: Installing development tools..."
sudo apt-get install -y \
    build-essential \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-$(uname -r) \
    git \
    python3 \
    python3-pip \
    bpfcc-tools \
    linux-headers-$(uname -r)

# Verify perf is working
echo ""
echo "Step 3: Verifying perf installation..."
if perf --version &>/dev/null; then
    echo "✓ perf is installed: $(perf --version)"
else
    echo "✗ perf installation failed"
    echo "Try: sudo apt-get install linux-tools-$(uname -r)"
fi

# Configure huge pages
echo ""
echo "Step 4: Configuring Transparent Huge Pages..."
echo "Current THP status:"
cat /sys/kernel/mm/transparent_hugepage/enabled

echo "Enabling THP (always)..."
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled

echo "THP defrag setting:"
cat /sys/kernel/mm/transparent_hugepage/defrag

# Disable swap for consistent performance
echo ""
echo "Step 5: Disabling swap..."
sudo swapoff -a
echo "✓ Swap disabled"

# Set CPU governor to performance mode
echo ""
echo "Step 6: Setting CPU governor to performance mode..."
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [ -f "$cpu" ]; then
        echo performance | sudo tee "$cpu" > /dev/null
    fi
done
echo "✓ CPU governor set to performance"

# Check system information
echo ""
echo "=========================================="
echo "System Information"
echo "=========================================="

echo "Kernel version:"
uname -r

echo ""
echo "CPU information:"
lscpu | grep -E "^Model name|^CPU\(s\)|^Thread|^Core"

echo ""
echo "Memory information:"
free -h

echo ""
echo "Huge pages configuration:"
cat /proc/meminfo | grep -i huge

echo ""
echo "Page size:"
getconf PAGESIZE

# Create workspace
echo ""
echo "=========================================="
echo "Setting up workspace"
echo "=========================================="

WORKSPACE=~/ecs251-project
mkdir -p $WORKSPACE
cd $WORKSPACE

echo "Workspace created at: $WORKSPACE"

# Check if in a git repository
if [ ! -d .git ]; then
    echo ""
    echo "Initializing git repository..."
    git init
    git config user.name "Your Name"
    git config user.email "your.email@example.com"
    echo "✓ Git repository initialized"
    echo "  Remember to set your name and email:"
    echo "    git config user.name \"Your Name\""
    echo "    git config user.email \"your.email@example.com\""
fi

# Create .gitignore
cat > .gitignore << 'EOF'
# Compiled files
*.o
benchmark
*.out

# Results
*.txt
*.csv
*.dat

# Temporary files
*.swp
*.swo
*~

# IDE files
.vscode/
.idea/

# System files
.DS_Store
EOF

echo "✓ .gitignore created"

# Create a README
cat > README.md << 'EOF'
# ECS251 Process Creation Benchmark

Quantitative comparison of fork(), vfork(), and posix_spawn() system calls.

## Team Members
- Abhijeet Rastogi
- Haochen Dong  
- Mahima Rudrapati

## Building

```bash
make
```

## Running

```bash
make run
```

## System Setup

Run the setup script once:
```bash
./setup_system.sh
```

## Project Structure

- `benchmark.c` - Main benchmark implementation
- `Makefile` - Build configuration
- `setup_system.sh` - System configuration script
- `run_experiments.sh` - Script to run all experiments

## Requirements

- Ubuntu 22.04 LTS
- Linux kernel 5.15+
- Minimum 32GB RAM
- perf and eBPF tools
EOF

echo "✓ README.md created"

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Copy your benchmark.c and Makefile to this directory"
echo "2. Build the benchmark: make"
echo "3. Run initial test: make test"
echo "4. Check system is configured: make check-hugepages"
echo ""
echo "Working directory: $WORKSPACE"
