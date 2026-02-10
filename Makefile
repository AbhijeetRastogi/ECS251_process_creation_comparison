CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu11
LDFLAGS = -lm

TARGET = benchmark
TEST_TARGET = quick_test
SOURCES = benchmark.c
TEST_SOURCES = quick_test.c
OBJECTS = $(SOURCES:.c=.o)
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)

.PHONY: all clean run setup check-hugepages test

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_TARGET): $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Check system configuration
check-hugepages:
	@echo "=== Checking Huge Pages Configuration ==="
	@echo "Transparent Huge Pages status:"
	@cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo "Not available"
	@echo ""
	@echo "Huge page pool:"
	@cat /proc/meminfo | grep -i huge || echo "No huge pages configured"
	@echo ""
	@echo "Page sizes:"
	@getconf PAGESIZE

# Setup system for benchmarking (requires root)
setup:
	@echo "=== Setting up system for benchmarking ==="
	@echo "Enabling transparent huge pages..."
	@echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
	@echo "Disabling swap to prevent interference..."
	@sudo swapoff -a || true
	@echo "Setting CPU governor to performance..."
	@echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || echo "CPU governor not available"
	@echo "Setup complete!"

# Run the benchmark
run: $(TARGET)
	./$(TARGET) | tee benchmark_results.txt

# Run a quick test with smaller memory sizes
test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET) $(OBJECTS) $(TEST_OBJECTS) benchmark_results.txt *.csv

# Build and run
all-run: all run
