#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <spawn.h>
#include <errno.h>
#include <sys/stat.h>

extern char **environ;

#define PAGE_SIZE_4KB (4 * 1024)
#define PAGE_SIZE_2MB (2 * 1024 * 1024)
#define NUM_ITERATIONS 100

static const size_t MEMORY_SIZES[] = {4, 8, 16};
#define NUM_MEMORY_SIZES (sizeof(MEMORY_SIZES) / sizeof(MEMORY_SIZES[0]))

#define MEMORY_SAFETY_PERCENT 80

static FILE *g_log_file = NULL;
static FILE *g_csv_file = NULL;

#define LOGF(...) \
    do { \
        printf(__VA_ARGS__); \
        if (g_log_file) { \
            fprintf(g_log_file, __VA_ARGS__); \
            fflush(g_log_file); \
        } \
    } while (0)

typedef struct {
    uint64_t latency_ns;
} iteration_data_t;

typedef struct {
    size_t memory_gb;
    size_t page_size;
    const char *method;
    double mean_ns;
    double stddev_ns;
    double p99_ns;
    double min_ns;
    double max_ns;
} result_t;

static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static size_t get_free_memory_gb(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    size_t kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemAvailable: %zu kB", &kb) == 1) break;
    }
    fclose(f);
    return kb / (1024 * 1024);
}

static int memory_size_is_safe(size_t size_gb) {
    size_t free_gb = get_free_memory_gb();
    if (free_gb == 0) return 1;
    return (size_gb * 100) <= (free_gb * MEMORY_SAFETY_PERCENT);
}

void *allocate_and_touch_memory(size_t size_bytes, int use_huge_pages) {
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    
    if (use_huge_pages) {
        void *mem = mmap(NULL, size_bytes, PROT_READ | PROT_WRITE, 
                         flags | MAP_HUGETLB, -1, 0);
        if (mem != MAP_FAILED) {
            LOGF("  Using MAP_HUGETLB\n");
            size_t page_size = PAGE_SIZE_2MB;
            for (size_t offset = 0; offset < size_bytes; offset += page_size)
                ((char *)mem)[offset] = 1;
            return mem;
        }
        LOGF("  MAP_HUGETLB failed, falling back to MADV_HUGEPAGE\n");
    }
    
    void *mem = mmap(NULL, size_bytes, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (mem == MAP_FAILED) { 
        perror("mmap failed"); 
        return NULL; 
    }
    
    if (use_huge_pages) {
        if (madvise(mem, size_bytes, MADV_HUGEPAGE) != 0) {
            perror("madvise MADV_HUGEPAGE failed");
        }
    }
    
    size_t page_size = use_huge_pages ? PAGE_SIZE_2MB : PAGE_SIZE_4KB;
    
    LOGF("  Touching %zu GB of memory with %s pages...\n", 
         size_bytes / (1024ULL * 1024 * 1024),
         use_huge_pages ? "2MB" : "4KB");
    
    uint64_t start = get_time_ns();
    for (size_t offset = 0; offset < size_bytes; offset += page_size)
        ((char *)mem)[offset] = 1;
    uint64_t end = get_time_ns();
    
    LOGF("  Memory touch completed in %.2f seconds\n", (end - start) / 1e9);
    return mem;
}

void calculate_stats(iteration_data_t *data, int count, result_t *result) {
    uint64_t sum = 0;
    result->min_ns = (double)data[0].latency_ns;
    result->max_ns = (double)data[0].latency_ns;
    
    for (int i = 0; i < count; i++) {
        sum += data[i].latency_ns;
        if (data[i].latency_ns < result->min_ns) result->min_ns = data[i].latency_ns;
        if (data[i].latency_ns > result->max_ns) result->max_ns = data[i].latency_ns;
    }
    result->mean_ns = (double)sum / count;
    
    double variance = 0;
    for (int i = 0; i < count; i++) {
        double diff = (double)data[i].latency_ns - result->mean_ns;
        variance += diff * diff;
    }
    result->stddev_ns = sqrt(variance / count);
    
    uint64_t *sorted = malloc(count * sizeof(uint64_t));
    for (int i = 0; i < count; i++) sorted[i] = data[i].latency_ns;
    for (int i = 0; i < count - 1; i++)
        for (int j = 0; j < count - i - 1; j++)
            if (sorted[j] > sorted[j+1]) {
                uint64_t tmp = sorted[j]; 
                sorted[j] = sorted[j+1]; 
                sorted[j+1] = tmp;
            }
    int p99_idx = (int)(count * 0.99);
    if (p99_idx >= count) p99_idx = count - 1;
    result->p99_ns = (double)sorted[p99_idx];
    free(sorted);
}

int benchmark_fork(iteration_data_t *data, int iterations) {
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        pid_t child = fork();
        if (child < 0) { 
            perror("fork failed"); 
            return -1; 
        }
        
        if (child == 0) {
            _exit(0);
        }
        
        uint64_t end = get_time_ns();
        data[i].latency_ns = end - start;
        
        int status;
        waitpid(child, &status, 0);
        
        if ((i + 1) % 10 == 0) {
            LOGF("\r    Progress: %d/%d iterations (%.1f ms avg so far)", 
                 i + 1, iterations,
                 (double)(data[i].latency_ns) / 1e6);
            fflush(stdout);
        }
    }
    LOGF("\n");
    return 0;
}

int benchmark_vfork(iteration_data_t *data, int iterations) {
    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();
        pid_t child = vfork();
        if (child < 0) { 
            perror("vfork failed"); 
            return -1; 
        }
        
        if (child == 0) {
            _exit(0);
        }
        
        uint64_t end = get_time_ns();
        data[i].latency_ns = end - start;
        
        int status;
        waitpid(child, &status, 0);
    }
    return 0;
}

int benchmark_posix_spawn(iteration_data_t *data, int iterations) {
    char *argv[] = {"/bin/true", NULL};
    
    for (int i = 0; i < iterations; i++) {
        pid_t child;
        uint64_t start = get_time_ns();
        int ret = posix_spawn(&child, "/bin/true", NULL, NULL, argv, environ);
        uint64_t end = get_time_ns();
        
        if (ret != 0) {
            fprintf(stderr, "posix_spawn failed: %s\n", strerror(ret));
            return -1;
        }
        
        data[i].latency_ns = end - start;
        
        int status;
        waitpid(child, &status, 0);
    }
    return 0;
}

int run_benchmark(size_t memory_gb, int use_huge_pages, const char *method,
                  result_t *result) {
    
    if (!memory_size_is_safe(memory_gb)) {
        size_t free_gb = get_free_memory_gb();
        LOGF("\n[SKIP] %zu GB requires more than %d%% of available memory (%zu GB free).\n",
             memory_gb, MEMORY_SAFETY_PERCENT, free_gb);
        return -1;
    }
    
    LOGF("\n");
    LOGF("====================================================================\n");
    LOGF("  Testing: %s | %zu GB | %s pages\n",
         method, memory_gb, use_huge_pages ? "2MB huge" : "4KB regular");
    LOGF("====================================================================\n");
    
    size_t memory_bytes = memory_gb * 1024ULL * 1024ULL * 1024ULL;
    void *mem = allocate_and_touch_memory(memory_bytes, use_huge_pages);
    if (!mem) return -1;
    
    iteration_data_t *data = calloc(NUM_ITERATIONS, sizeof(iteration_data_t));
    if (!data) { 
        munmap(mem, memory_bytes); 
        return -1; 
    }
    
    LOGF("  Running %d iterations...\n", NUM_ITERATIONS);
    
    int ret = 0;
    if (strcmp(method, "fork") == 0) 
        ret = benchmark_fork(data, NUM_ITERATIONS);
    else if (strcmp(method, "vfork") == 0) 
        ret = benchmark_vfork(data, NUM_ITERATIONS);
    else if (strcmp(method, "posix_spawn") == 0) 
        ret = benchmark_posix_spawn(data, NUM_ITERATIONS);
    else { 
        fprintf(stderr, "Unknown method: %s\n", method); 
        ret = -1; 
    }
    
    if (ret == 0) {
        calculate_stats(data, NUM_ITERATIONS, result);
        result->memory_gb = memory_gb;
        result->page_size = use_huge_pages ? PAGE_SIZE_2MB : PAGE_SIZE_4KB;
        result->method = method;
        
        LOGF("\n  RESULTS:\n");
        LOGF("  Mean:   %10.3f ms\n", result->mean_ns / 1e6);
        LOGF("  StdDev: %10.3f ms\n", result->stddev_ns / 1e6);
        LOGF("  P99:    %10.3f ms\n", result->p99_ns / 1e6);
        LOGF("  Min:    %10.3f ms\n", result->min_ns / 1e6);
        LOGF("  Max:    %10.3f ms\n", result->max_ns / 1e6);
    }
    
    free(data);
    munmap(mem, memory_bytes);
    return ret;
}

int create_output_dir(char *dir_out, size_t dir_out_size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(dir_out, dir_out_size, "results_large_%04d%02d%02d_%02d%02d%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    if (mkdir(dir_out, 0755) != 0) { 
        perror("mkdir failed"); 
        return -1; 
    }
    printf(">>> Output directory: %s/\n", dir_out);
    return 0;
}

void print_results_csv(result_t *results, int count) {
    if (!g_csv_file) { 
        fprintf(stderr, "[ERROR] CSV file not open.\n"); 
        return; 
    }
    
    fprintf(g_csv_file, "Memory_GB,Page_Size,Method,Mean_ms,StdDev_ms,P99_ms,Min_ms,Max_ms\n");
    
    for (int i = 0; i < count; i++) {
        result_t *r = &results[i];
        fprintf(g_csv_file, "%zu,%s,%s,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                r->memory_gb,
                r->page_size == PAGE_SIZE_2MB ? "2MB" : "4KB",
                r->method,
                r->mean_ns / 1e6, 
                r->stddev_ns / 1e6,
                r->p99_ns / 1e6, 
                r->min_ns / 1e6, 
                r->max_ns / 1e6);
    }
    fflush(g_csv_file);
}

void print_summary_table(result_t *results, int count) {
    LOGF("\n");
    LOGF("======================================================================\n");
    LOGF("                    LARGE MEMORY BENCHMARK SUMMARY                    \n");
    LOGF("======================================================================\n");
    LOGF(" Memory | Pages | Method        | Mean (ms) | P99 (ms)  | StdDev    \n");
    LOGF("--------|-------|---------------|-----------|-----------|------------\n");
    
    for (int i = 0; i < count; i++) {
        result_t *r = &results[i];
        LOGF(" %4zu GB | %-5s | %-13s | %9.3f | %9.3f | %9.3f\n",
             r->memory_gb,
             r->page_size == PAGE_SIZE_2MB ? "2MB" : "4KB",
             r->method,
             r->mean_ns / 1e6,
             r->p99_ns / 1e6,
             r->stddev_ns / 1e6);
    }
    LOGF("======================================================================\n");
}

int main(int argc, char *argv[]) {
    
    LOGF("\n");
    LOGF("======================================================================\n");
    LOGF("     LARGE MEMORY PROCESS CREATION BENCHMARK (4GB - 16GB)            \n");
    LOGF("     fork() vs vfork() vs posix_spawn()                              \n");
    LOGF("======================================================================\n");
    LOGF("\n");
    
    char out_dir[64];
    if (create_output_dir(out_dir, sizeof(out_dir)) != 0) {
        fprintf(stderr, "Failed to create output directory.\n"); 
        return 1;
    }
    
    char log_path[128], csv_path[128];
    snprintf(log_path, sizeof(log_path), "%s/terminal.log", out_dir);
    snprintf(csv_path, sizeof(csv_path), "%s/results.csv", out_dir);
    
    g_log_file = fopen(log_path, "w");
    if (!g_log_file) 
        fprintf(stderr, "Warning: could not open %s\n", log_path);
    
    g_csv_file = fopen(csv_path, "w");
    if (!g_csv_file) {
        fprintf(stderr, "Failed to open CSV file %s\n", csv_path);
        if (g_log_file) fclose(g_log_file);
        return 1;
    }
    
    LOGF("Configuration:\n");
    LOGF("  Output directory : %s/\n", out_dir);
    LOGF("  Iterations       : %d per configuration\n", NUM_ITERATIONS);
    LOGF("  Memory sizes     : 4GB, 8GB, 16GB\n");
    LOGF("  Page sizes       : 4KB, 2MB\n");
    LOGF("  Methods          : fork, vfork, posix_spawn\n");
    LOGF("\n");
    
    size_t free_gb = get_free_memory_gb();
    LOGF("System Information:\n");
    LOGF("  Available memory : ~%zu GB\n", free_gb);
    LOGF("  Memory sizes to test:\n");
    for (size_t i = 0; i < NUM_MEMORY_SIZES; i++) {
        int safe = memory_size_is_safe(MEMORY_SIZES[i]);
        LOGF("    - %2zu GB : %s\n", 
             MEMORY_SIZES[i], 
             safe ? "OK" : "SKIP (insufficient RAM)");
    }
    LOGF("\n");
    
    if (free_gb < 5) {
        LOGF("ERROR: Insufficient memory to run any large memory tests.\n");
        LOGF("       Need at least 5GB free RAM for 4GB test.\n");
        if (g_csv_file) fclose(g_csv_file);
        if (g_log_file) fclose(g_log_file);
        return 1;
    }
    
    const char *methods[] = {"fork", "vfork", "posix_spawn"};
    int total_tests = NUM_MEMORY_SIZES * 2 * 3;
    
    result_t *results = calloc(total_tests, sizeof(result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate results array\n");
        if (g_csv_file) fclose(g_csv_file);
        if (g_log_file) fclose(g_log_file);
        return 1;
    }
    
    LOGF("Starting benchmark...\n");
    
    int result_idx = 0;
    for (size_t mem_idx = 0; mem_idx < NUM_MEMORY_SIZES; mem_idx++) {
        size_t memory_gb = MEMORY_SIZES[mem_idx];
        for (int use_huge = 0; use_huge <= 1; use_huge++) {
            for (int m = 0; m < 3; m++) {
                if (run_benchmark(memory_gb, use_huge, methods[m],
                                  &results[result_idx]) == 0)
                    result_idx++;
            }
        }
    }
    
    if (result_idx == 0) {
        LOGF("\nNo tests completed. Please use a machine with more RAM.\n");
    } else {
        print_results_csv(results, result_idx);
        print_summary_table(results, result_idx);
        
        LOGF("\n");
        LOGF("BENCHMARK COMPLETE\n");
        LOGF("Results saved to: %s/\n", out_dir);
    }
    
    free(results);
    if (g_csv_file) fclose(g_csv_file);
    if (g_log_file) fclose(g_log_file);
    return 0;
}
