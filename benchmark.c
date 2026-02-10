#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <spawn.h>

// External environment variable for posix_spawn
extern char **environ;

// Configuration constants
#define PAGE_SIZE_4KB (4 * 1024)
#define PAGE_SIZE_2MB (2 * 1024 * 1024)
#define NUM_ITERATIONS 100

// Memory sizes to test (in GB)
static const size_t MEMORY_SIZES[] = {1, 2};
#define NUM_MEMORY_SIZES (sizeof(MEMORY_SIZES) / sizeof(MEMORY_SIZES[0]))

// Statistics structure
typedef struct {
    double mean_ns;
    double stddev_ns;
    double percentile_99_ns;
    double min_ns;
    double max_ns;
} stats_t;

// Result structure
typedef struct {
    size_t memory_gb;
    size_t page_size;
    const char *method;
    stats_t stats;
} result_t;

/**
 * Allocate and touch memory to defeat lazy allocation
 * Returns pointer to allocated memory or NULL on failure
 */
void* allocate_and_touch_memory(size_t size_bytes, int use_huge_pages) {
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    
    // Allocate memory
    void *mem = mmap(NULL, size_bytes, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return NULL;
    }
    
    // Configure huge pages if requested
    if (use_huge_pages) {
        if (madvise(mem, size_bytes, MADV_HUGEPAGE) != 0) {
            perror("madvise MADV_HUGEPAGE failed");
            munmap(mem, size_bytes);
            return NULL;
        }
    }
    
    // Touch every page by writing one byte per page
    size_t page_size = use_huge_pages ? PAGE_SIZE_2MB : PAGE_SIZE_4KB;
    for (size_t offset = 0; offset < size_bytes; offset += page_size) {
        ((char*)mem)[offset] = 1;
    }
    
    printf("  Allocated and touched %zu MB (%s pages)\n", 
           size_bytes / (1024*1024),
           use_huge_pages ? "2MB huge" : "4KB regular");
    
    return mem;
}

/**
 * Get high-resolution timestamp in nanoseconds
 */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/**
 * Calculate statistics from an array of measurements
 */
void calculate_stats(uint64_t *measurements, int count, stats_t *stats) {
    // Calculate mean
    uint64_t sum = 0;
    stats->min_ns = measurements[0];
    stats->max_ns = measurements[0];
    
    for (int i = 0; i < count; i++) {
        sum += measurements[i];
        if (measurements[i] < stats->min_ns) stats->min_ns = measurements[i];
        if (measurements[i] > stats->max_ns) stats->max_ns = measurements[i];
    }
    stats->mean_ns = (double)sum / count;
    
    // Calculate standard deviation
    double variance = 0;
    for (int i = 0; i < count; i++) {
        double diff = measurements[i] - stats->mean_ns;
        variance += diff * diff;
    }
    stats->stddev_ns = sqrt(variance / count);
    
    // Calculate 99th percentile (need to sort first)
    uint64_t *sorted = malloc(count * sizeof(uint64_t));
    memcpy(sorted, measurements, count * sizeof(uint64_t));
    
    // Simple bubble sort (fine for 100 elements)
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (sorted[j] > sorted[j + 1]) {
                uint64_t temp = sorted[j];
                sorted[j] = sorted[j + 1];
                sorted[j + 1] = temp;
            }
        }
    }
    
    int p99_idx = (int)(count * 0.99);
    if (p99_idx >= count) p99_idx = count - 1;
    stats->percentile_99_ns = sorted[p99_idx];
    
    free(sorted);
}

/**
 * Benchmark fork() system call
 */
int benchmark_fork(uint64_t *measurements, int iterations) {
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork failed");
            return -1;
        }
        
        if (pid == 0) {
            // Child process - exit immediately
            _exit(0);
        } else {
            // Parent process - measure time until fork returns
            uint64_t end = get_time_ns();
            measurements[i] = end - start;
            
            // Wait for child to prevent zombies
            int status;
            waitpid(pid, &status, 0);
        }
    }
    return 0;
}

/**
 * Benchmark vfork() system call
 */
int benchmark_vfork(uint64_t *measurements, int iterations) {
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        
        pid_t pid = vfork();
        if (pid < 0) {
            perror("vfork failed");
            return -1;
        }
        
        if (pid == 0) {
            // Child process - exit immediately
            // Must use _exit() not exit() with vfork
            _exit(0);
        } else {
            // Parent process
            uint64_t end = get_time_ns();
            measurements[i] = end - start;
            
            // Wait for child
            int status;
            waitpid(pid, &status, 0);
        }
    }
    return 0;
}

/**
 * Benchmark posix_spawn() system call
 */
int benchmark_posix_spawn(uint64_t *measurements, int iterations) {
    char *argv[] = {"/bin/true", NULL};
    
    for (int i = 0; i < iterations; i++) {
        pid_t pid;
        
        uint64_t start = get_time_ns();
        
        int ret = posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ);
        
        uint64_t end = get_time_ns();
        
        if (ret != 0) {
            fprintf(stderr, "posix_spawn failed: %s\n", strerror(ret));
            return -1;
        }
        
        measurements[i] = end - start;
        
        // Wait for child
        int status;
        waitpid(pid, &status, 0);
    }
    return 0;
}

/**
 * Run a single benchmark configuration
 */
int run_benchmark(size_t memory_gb, int use_huge_pages, const char *method,
                  result_t *result) {
    printf("\n=== Testing %s with %zu GB (%s pages) ===\n",
           method, memory_gb,
           use_huge_pages ? "2MB huge" : "4KB regular");
    
    // Allocate and touch memory
    size_t memory_bytes = memory_gb * 1024ULL * 1024ULL * 1024ULL;
    void *mem = allocate_and_touch_memory(memory_bytes, use_huge_pages);
    if (!mem) {
        return -1;
    }
    
    // Allocate measurement array
    uint64_t *measurements = malloc(NUM_ITERATIONS * sizeof(uint64_t));
    if (!measurements) {
        munmap(mem, memory_bytes);
        return -1;
    }
    
    // Run the benchmark
    int ret = 0;
    printf("  Running %d iterations...\n", NUM_ITERATIONS);
    
    if (strcmp(method, "fork") == 0) {
        ret = benchmark_fork(measurements, NUM_ITERATIONS);
    } else if (strcmp(method, "vfork") == 0) {
        ret = benchmark_vfork(measurements, NUM_ITERATIONS);
    } else if (strcmp(method, "posix_spawn") == 0) {
        ret = benchmark_posix_spawn(measurements, NUM_ITERATIONS);
    } else {
        fprintf(stderr, "Unknown method: %s\n", method);
        ret = -1;
    }
    
    if (ret == 0) {
        // Calculate statistics
        calculate_stats(measurements, NUM_ITERATIONS, &result->stats);
        result->memory_gb = memory_gb;
        result->page_size = use_huge_pages ? PAGE_SIZE_2MB : PAGE_SIZE_4KB;
        result->method = method;
        
        printf("  Mean: %.3f ms, StdDev: %.3f ms, 99th%%: %.3f ms\n",
               result->stats.mean_ns / 1e6,
               result->stats.stddev_ns / 1e6,
               result->stats.percentile_99_ns / 1e6);
    }
    
    // Cleanup
    free(measurements);
    munmap(mem, memory_bytes);
    
    return ret;
}

/**
 * Print results in CSV format
 */
void print_results_csv(result_t *results, int count) {
    printf("\n=== Results (CSV format) ===\n");
    printf("Memory_GB,Page_Size,Method,Mean_ms,StdDev_ms,P99_ms,Min_ms,Max_ms\n");
    
    for (int i = 0; i < count; i++) {
        result_t *r = &results[i];
        printf("%zu,%s,%s,%.6f,%.6f,%.6f,%.6f,%.6f\n",
               r->memory_gb,
               r->page_size == PAGE_SIZE_2MB ? "2MB" : "4KB",
               r->method,
               r->stats.mean_ns / 1e6,
               r->stats.stddev_ns / 1e6,
               r->stats.percentile_99_ns / 1e6,
               r->stats.min_ns / 1e6,
               r->stats.max_ns / 1e6);
    }
}

int main(int argc, char *argv[]) {
    printf("Process Creation Benchmark\n");
    printf("===========================\n");
    printf("Iterations per configuration: %d\n", NUM_ITERATIONS);
    printf("Memory sizes: ");
    for (size_t i = 0; i < NUM_MEMORY_SIZES; i++) {
        printf("%zu GB%s", MEMORY_SIZES[i], 
               i < NUM_MEMORY_SIZES - 1 ? ", " : "\n");
    }
    
    // Calculate total number of tests
    const char *methods[] = {"fork", "vfork", "posix_spawn"};
    int num_methods = 3;
    int num_page_types = 2; // 4KB and 2MB
    int total_tests = NUM_MEMORY_SIZES * num_page_types * num_methods;
    
    // Allocate results array
    result_t *results = malloc(total_tests * sizeof(result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate results array\n");
        return 1;
    }
    
    int result_idx = 0;
    
    // Run all benchmarks
    for (size_t mem_idx = 0; mem_idx < NUM_MEMORY_SIZES; mem_idx++) {
        size_t memory_gb = MEMORY_SIZES[mem_idx];
        
        for (int use_huge = 0; use_huge <= 1; use_huge++) {
            for (int method_idx = 0; method_idx < num_methods; method_idx++) {
                if (run_benchmark(memory_gb, use_huge, 
                                methods[method_idx],
                                &results[result_idx]) == 0) {
                    result_idx++;
                } else {
                    fprintf(stderr, "Benchmark failed, continuing...\n");
                }
            }
        }
    }
    
    // Print all results
    print_results_csv(results, result_idx);
    
    free(results);
    
    printf("\n=== Benchmark Complete ===\n");
    return 0;
}
