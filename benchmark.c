#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <spawn.h>
#include <math.h>

#include "tracer.h"
#include "ebpf_tracer.h"

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

extern char **environ;

/* -------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */
#define PAGE_SIZE_4KB   (4 * 1024)
#define PAGE_SIZE_2MB   (2 * 1024 * 1024)
#define NUM_ITERATIONS  100
#define BPF_OBJ_PATH    "./tracer.bpf.o"

static const size_t MEMORY_SIZES[] = {1, 2};
#define NUM_MEMORY_SIZES (sizeof(MEMORY_SIZES) / sizeof(MEMORY_SIZES[0]))

/* -------------------------------------------------------------------------
 * Data structures
 * ------------------------------------------------------------------------- */
typedef struct {
    uint64_t latency_ns;
    struct ebpf_metrics ebpf;   /* combined parent + child metrics */
} iteration_data_t;

typedef struct {
    size_t      memory_gb;
    size_t      page_size;
    const char *method;

    double mean_ns;
    double stddev_ns;
    double p99_ns;
    double min_ns;
    double max_ns;

    double mean_pf_user;
    double mean_pf_kernel;
    double mean_pf_total;
    double mean_tlb_total;
    double mean_tlb_remote_shootdown;
    double mean_tlb_local_shootdown;
    double mean_tlb_local_mm;
    double mean_tlb_remote_ipi;
    double mean_tlb_task_switch;
} result_t;

static tracer_ctx_t *g_tracer = NULL;

/* -------------------------------------------------------------------------
 * Utility
 * ------------------------------------------------------------------------- */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * merge_metrics() — add child's counters into the parent's metrics struct.
 *
 * WHY THIS IS NEEDED:
 *   Kernel events during fork() are attributed to two different PIDs:
 *
 *   Parent PID receives:
 *     - Kernel page faults from copying page table entries inside fork()
 *     - TLB shootdowns issued to other CPUs as pages are marked CoW
 *
 *   Child PID receives:
 *     - User page faults when the child (or parent) writes to a CoW page,
 *       triggering the actual physical memory copy
 *     - TLB events in the child's own context after fork returns
 *
 *   Watching only the parent misses the child's share of the cost.
 *   We merge both into one total to represent the true per-iteration expense.
 */
static void merge_metrics(struct ebpf_metrics *dst,
                          const struct ebpf_metrics *child) {
    dst->page_faults_user      += child->page_faults_user;
    dst->page_faults_kernel    += child->page_faults_kernel;
    dst->tlb_flush_task_switch += child->tlb_flush_task_switch;
    dst->tlb_remote_shootdown  += child->tlb_remote_shootdown;
    dst->tlb_local_shootdown   += child->tlb_local_shootdown;
    dst->tlb_local_mm          += child->tlb_local_mm;
    dst->tlb_remote_ipi_sent   += child->tlb_remote_ipi_sent;
    dst->tlb_total             += child->tlb_total;
}

void *allocate_and_touch_memory(size_t size_bytes, int use_huge_pages) {
    int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    void *mem = mmap(NULL, size_bytes, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (mem == MAP_FAILED) { perror("mmap failed"); return NULL; }

    if (use_huge_pages) {
        if (madvise(mem, size_bytes, MADV_HUGEPAGE) != 0) {
            perror("madvise MADV_HUGEPAGE failed");
            munmap(mem, size_bytes);
            return NULL;
        }
    }

    size_t page_size = use_huge_pages ? PAGE_SIZE_2MB : PAGE_SIZE_4KB;
    for (size_t offset = 0; offset < size_bytes; offset += page_size)
        ((char *)mem)[offset] = 1;

    LOGF("  Allocated and touched %zu MB (%s pages)\n",
         size_bytes / (1024 * 1024),
         use_huge_pages ? "2MB huge" : "4KB regular");
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
                uint64_t tmp = sorted[j]; sorted[j] = sorted[j+1]; sorted[j+1] = tmp;
            }
    int p99_idx = (int)(count * 0.99);
    if (p99_idx >= count) p99_idx = count - 1;
    result->p99_ns = (double)sorted[p99_idx];
    free(sorted);

    double sum_pf_user = 0, sum_pf_kernel = 0;
    double sum_tlb_total = 0, sum_tlb_remote = 0;
    double sum_tlb_local = 0, sum_tlb_local_mm = 0;
    double sum_tlb_ipi = 0, sum_tlb_task = 0;

    for (int i = 0; i < count; i++) {
        struct ebpf_metrics *m = &data[i].ebpf;
        sum_pf_user      += m->page_faults_user;
        sum_pf_kernel    += m->page_faults_kernel;
        sum_tlb_total    += m->tlb_total;
        sum_tlb_remote   += m->tlb_remote_shootdown;
        sum_tlb_local    += m->tlb_local_shootdown;
        sum_tlb_local_mm += m->tlb_local_mm;
        sum_tlb_ipi      += m->tlb_remote_ipi_sent;
        sum_tlb_task     += m->tlb_flush_task_switch;
    }

    result->mean_pf_user              = sum_pf_user      / count;
    result->mean_pf_kernel            = sum_pf_kernel    / count;
    result->mean_pf_total             = (sum_pf_user + sum_pf_kernel) / count;
    result->mean_tlb_total            = sum_tlb_total    / count;
    result->mean_tlb_remote_shootdown = sum_tlb_remote   / count;
    result->mean_tlb_local_shootdown  = sum_tlb_local    / count;
    result->mean_tlb_local_mm         = sum_tlb_local_mm / count;
    result->mean_tlb_remote_ipi       = sum_tlb_ipi      / count;
    result->mean_tlb_task_switch      = sum_tlb_task     / count;
}

/* -------------------------------------------------------------------------
 * Benchmark functions
 *
 * All three now follow the same corrected pattern:
 *   1. Reset parent metrics
 *   2. Create child process — record start/end timestamps in parent
 *   3. Register child PID with tracer immediately after it is known
 *   4. Read parent metrics
 *   5. waitpid() — child has now fully exited
 *   6. Read child metrics and merge into parent's struct
 *   7. Unwatch child PID
 * ------------------------------------------------------------------------- */

int benchmark_fork(iteration_data_t *data, int iterations, int parent_pid) {
    for (int i = 0; i < iterations; i++) {

        if (g_tracer) tracer_reset_metrics(g_tracer, parent_pid);

        uint64_t start = get_time_ns();
        pid_t child = fork();
        if (child < 0) { perror("fork failed"); return -1; }

        if (child == 0) {
            /* Child: exit immediately. _exit() skips C library cleanup,
             * which is safer and avoids any stdio buffer interference. */
            _exit(0);
        }

        uint64_t end = get_time_ns();
        data[i].latency_ns = end - start;

        if (g_tracer) {
            tracer_watch_pid(g_tracer, child);
            tracer_read_metrics(g_tracer, parent_pid, &data[i].ebpf);

            int status;
            waitpid(child, &status, 0);

            struct ebpf_metrics child_m = {0};
            tracer_read_metrics(g_tracer, child, &child_m);
            merge_metrics(&data[i].ebpf, &child_m);
            tracer_unwatch_pid(g_tracer, child);
        } else {
            int status;
            waitpid(child, &status, 0);
        }
    }
    return 0;
}

int benchmark_vfork(iteration_data_t *data, int iterations, int parent_pid) {
    for (int i = 0; i < iterations; i++) {

        if (g_tracer) tracer_reset_metrics(g_tracer, parent_pid);

        uint64_t start = get_time_ns();
        pid_t child = vfork();
        if (child < 0) { perror("vfork failed"); return -1; }

        if (child == 0) {
            /* vfork child shares parent memory — parent is frozen until
             * we call _exit(). Must not touch any variables or call
             * any library functions. */
            _exit(0);
        }

        /* Parent resumes here only after child has called _exit() */
        uint64_t end = get_time_ns();
        data[i].latency_ns = end - start;

        if (g_tracer) {
            tracer_watch_pid(g_tracer, child);
            tracer_read_metrics(g_tracer, parent_pid, &data[i].ebpf);

            int status;
            waitpid(child, &status, 0);

            struct ebpf_metrics child_m = {0};
            tracer_read_metrics(g_tracer, child, &child_m);
            merge_metrics(&data[i].ebpf, &child_m);
            tracer_unwatch_pid(g_tracer, child);
        } else {
            int status;
            waitpid(child, &status, 0);
        }
    }
    return 0;
}

int benchmark_posix_spawn(iteration_data_t *data, int iterations, int parent_pid) {
    char *argv[] = {"/bin/true", NULL};

    for (int i = 0; i < iterations; i++) {

        if (g_tracer) tracer_reset_metrics(g_tracer, parent_pid);

        pid_t child;
        uint64_t start = get_time_ns();
        int ret = posix_spawn(&child, "/bin/true", NULL, NULL, argv, environ);
        uint64_t end = get_time_ns();

        if (ret != 0) {
            fprintf(stderr, "posix_spawn failed: %s\n", strerror(ret));
            return -1;
        }

        data[i].latency_ns = end - start;

        if (g_tracer) {
            tracer_watch_pid(g_tracer, child);
            tracer_read_metrics(g_tracer, parent_pid, &data[i].ebpf);

            int status;
            waitpid(child, &status, 0);

            struct ebpf_metrics child_m = {0};
            tracer_read_metrics(g_tracer, child, &child_m);
            merge_metrics(&data[i].ebpf, &child_m);
            tracer_unwatch_pid(g_tracer, child);
        } else {
            int status;
            waitpid(child, &status, 0);
        }
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Benchmark runner
 * ------------------------------------------------------------------------- */
int run_benchmark(size_t memory_gb, int use_huge_pages, const char *method,
                  result_t *result) {

    LOGF("\n=== Testing %s | %zu GB | %s pages ===\n",
         method, memory_gb, use_huge_pages ? "2MB huge" : "4KB regular");

    size_t memory_bytes = memory_gb * 1024ULL * 1024ULL * 1024ULL;
    void *mem = allocate_and_touch_memory(memory_bytes, use_huge_pages);
    if (!mem) return -1;

    iteration_data_t *data = calloc(NUM_ITERATIONS, sizeof(iteration_data_t));
    if (!data) { munmap(mem, memory_bytes); return -1; }

    int my_pid = (int)getpid();
    if (g_tracer) tracer_watch_pid(g_tracer, my_pid);

    LOGF("  Running %d iterations...\n", NUM_ITERATIONS);

    int ret = 0;
    if      (strcmp(method, "fork")        == 0) ret = benchmark_fork(data, NUM_ITERATIONS, my_pid);
    else if (strcmp(method, "vfork")       == 0) ret = benchmark_vfork(data, NUM_ITERATIONS, my_pid);
    else if (strcmp(method, "posix_spawn") == 0) ret = benchmark_posix_spawn(data, NUM_ITERATIONS, my_pid);
    else { fprintf(stderr, "Unknown method: %s\n", method); ret = -1; }

    if (g_tracer) tracer_unwatch_pid(g_tracer, my_pid);

    if (ret == 0) {
        calculate_stats(data, NUM_ITERATIONS, result);
        result->memory_gb = memory_gb;
        result->page_size = use_huge_pages ? PAGE_SIZE_2MB : PAGE_SIZE_4KB;
        result->method    = method;

        LOGF("  Latency    | Mean: %8.3f ms  StdDev: %8.3f ms  P99: %8.3f ms\n",
             result->mean_ns / 1e6, result->stddev_ns / 1e6, result->p99_ns / 1e6);
        if (g_tracer) {
            LOGF("  PageFaults | User: %6.1f  Kernel: %6.1f  Total: %6.1f\n",
                 result->mean_pf_user, result->mean_pf_kernel, result->mean_pf_total);
            LOGF("  TLB Flush  | Total: %6.1f  RemoteShootdown: %6.1f"
                 "  LocalShootdown: %6.1f\n",
                 result->mean_tlb_total,
                 result->mean_tlb_remote_shootdown,
                 result->mean_tlb_local_shootdown);
            LOGF("             | LocalMM: %6.1f  RemoteIPI: %6.1f"
                 "  TaskSwitch: %6.1f\n",
                 result->mean_tlb_local_mm,
                 result->mean_tlb_remote_ipi,
                 result->mean_tlb_task_switch);
        }
    } else {
        LOGF("Benchmark failed for %s, continuing...\n", method);
    }

    free(data);
    munmap(mem, memory_bytes);
    return ret;
}

/* -------------------------------------------------------------------------
 * Output directory
 * ------------------------------------------------------------------------- */
int create_output_dir(char *dir_out, size_t dir_out_size) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(dir_out, dir_out_size, "results_%04d%02d%02d_%02d%02d%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);
    if (mkdir(dir_out, 0755) != 0) { perror("mkdir failed"); return -1; }
    printf(">>> Output directory: %s/\n", dir_out);
    return 0;
}

/* -------------------------------------------------------------------------
 * CSV output
 * ------------------------------------------------------------------------- */
void print_results_csv(result_t *results, int count, int has_ebpf) {
    if (!g_csv_file) { fprintf(stderr, "[ERROR] CSV file not open.\n"); return; }

    fprintf(g_csv_file,
            "Memory_GB,Page_Size,Method,Mean_ms,StdDev_ms,P99_ms,Min_ms,Max_ms");
    if (has_ebpf)
        fprintf(g_csv_file,
                ",PF_User,PF_Kernel,PF_Total"
                ",TLB_Total,TLB_RemoteShootdown,TLB_LocalShootdown"
                ",TLB_LocalMM,TLB_RemoteIPI,TLB_TaskSwitch");
    fprintf(g_csv_file, "\n");

    for (int i = 0; i < count; i++) {
        result_t *r = &results[i];
        fprintf(g_csv_file, "%zu,%s,%s,%.6f,%.6f,%.6f,%.6f,%.6f",
                r->memory_gb,
                r->page_size == PAGE_SIZE_2MB ? "2MB" : "4KB",
                r->method,
                r->mean_ns / 1e6, r->stddev_ns / 1e6,
                r->p99_ns  / 1e6, r->min_ns    / 1e6, r->max_ns / 1e6);
        if (has_ebpf)
            fprintf(g_csv_file, ",%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f",
                    r->mean_pf_user, r->mean_pf_kernel, r->mean_pf_total,
                    r->mean_tlb_total, r->mean_tlb_remote_shootdown,
                    r->mean_tlb_local_shootdown, r->mean_tlb_local_mm,
                    r->mean_tlb_remote_ipi, r->mean_tlb_task_switch);
        fprintf(g_csv_file, "\n");
    }
    fflush(g_csv_file);
    LOGF("\n>>> CSV results saved.\n");
}

/* -------------------------------------------------------------------------
 * Legend
 * ------------------------------------------------------------------------- */
void print_ebpf_legend(void) {
    LOGF("\n=== eBPF Metrics Legend ===\n");
    LOGF("  NOTE: all metrics are the SUM of parent + child PID events per\n");
    LOGF("        iteration, giving the true total cost of process creation.\n\n");
    LOGF("  PF_User          - User page faults (CoW copies triggered by writes).\n");
    LOGF("  PF_Kernel        - Kernel page faults (page table copy work in fork).\n");
    LOGF("  PF_Total         - Sum of both.\n");
    LOGF("  TLB_Total        - All TLB flush events combined.\n");
    LOGF("  TLB_RemoteShoot  - Remote TLB shootdowns (expensive cross-CPU stalls).\n");
    LOGF("  TLB_LocalShoot   - This CPU flushing its own TLB.\n");
    LOGF("  TLB_LocalMM      - Full address-space TLB flush.\n");
    LOGF("  TLB_RemoteIPI    - IPI sent requesting remote CPU TLB flush.\n");
    LOGF("  TLB_TaskSwitch   - Flush on context switch (background noise).\n");
}

/* -------------------------------------------------------------------------
 * main()
 * ------------------------------------------------------------------------- */
int main(int argc, char *argv[]) {

    char out_dir[64];
    if (create_output_dir(out_dir, sizeof(out_dir)) != 0) {
        fprintf(stderr, "Failed to create output directory.\n"); return 1;
    }

    char log_path[128], csv_path[128];
    snprintf(log_path, sizeof(log_path), "%s/terminal.log", out_dir);
    snprintf(csv_path, sizeof(csv_path), "%s/results.csv",  out_dir);

    g_log_file = fopen(log_path, "w");
    if (!g_log_file) fprintf(stderr, "Warning: could not open %s\n", log_path);

    g_csv_file = fopen(csv_path, "w");
    if (!g_csv_file) {
        fprintf(stderr, "Failed to open CSV file %s\n", csv_path);
        if (g_log_file) fclose(g_log_file);
        return 1;
    }

    LOGF("Process Creation Benchmark with eBPF Kernel Tracing\n");
    LOGF("=====================================================\n");
    LOGF("Output directory : %s/\n", out_dir);
    LOGF("Log file         : %s\n",  log_path);
    LOGF("CSV file         : %s\n",  csv_path);
    LOGF("Iterations per configuration: %d\n", NUM_ITERATIONS);

    int ebpf_available = tracer_is_available();
    if (ebpf_available) {
        g_tracer = tracer_init(BPF_OBJ_PATH);
        if (!g_tracer) {
            LOGF("\n[WARNING] eBPF tracer init failed. Running in timing-only mode.\n\n");
            ebpf_available = 0;
        }
    } else {
        LOGF("\n[INFO] eBPF not available. Running in timing-only mode.\n\n");
    }

    const char *methods[] = {"fork", "vfork", "posix_spawn"};
    int total_tests = NUM_MEMORY_SIZES * 2 * 3;

    result_t *results = calloc(total_tests, sizeof(result_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate results array\n");
        if (g_tracer)   tracer_cleanup(g_tracer);
        if (g_csv_file) fclose(g_csv_file);
        if (g_log_file) fclose(g_log_file);
        return 1;
    }

    int result_idx = 0;
    for (size_t mem_idx = 0; mem_idx < NUM_MEMORY_SIZES; mem_idx++) {
        size_t memory_gb = MEMORY_SIZES[mem_idx];
        for (int use_huge = 0; use_huge <= 1; use_huge++) {
            for (int m = 0; m < 3; m++) {
                if (run_benchmark(memory_gb, use_huge, methods[m],
                                  &results[result_idx]) == 0)
                    result_idx++;
                else
                    LOGF("Benchmark failed for %s %zuGB %s, continuing...\n",
                         methods[m], memory_gb, use_huge ? "2MB" : "4KB");
            }
        }
    }

    print_results_csv(results, result_idx, ebpf_available);
    if (ebpf_available) print_ebpf_legend();

    free(results);
    if (g_tracer)   tracer_cleanup(g_tracer);

    LOGF("\n=== Benchmark Complete ===\n");
    LOGF("Results saved to: %s/\n", out_dir);

    if (g_csv_file) fclose(g_csv_file);
    if (g_log_file) fclose(g_log_file);
    return 0;
}