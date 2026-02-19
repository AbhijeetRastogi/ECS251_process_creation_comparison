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

/* perf_event_open() is a raw Linux syscall — no glibc wrapper exists.
 * We include the kernel header and call it via syscall(2) directly. */
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

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

/*
 * Memory sizes to benchmark (in GB).
 *
 * The benchmark checks available RAM at startup and skips sizes that
 * would require more than 80% of free memory, so it is safe to list
 * the full range here even on smaller machines.
 */
static const size_t MEMORY_SIZES[] = {1, 2, 4, 8, 16};
#define NUM_MEMORY_SIZES (sizeof(MEMORY_SIZES) / sizeof(MEMORY_SIZES[0]))

/* -------------------------------------------------------------------------
 * Data structures
 * ------------------------------------------------------------------------- */

/*
 * Hardware performance counters collected via perf_event_open().
 *
 * We open one file descriptor per counter before each iteration and read
 * the delta after. This is more accurate than `perf stat` (which wraps the
 * entire process) because we can isolate exactly the syscall under test.
 *
 * Counters chosen:
 *   - cpu-cycles          : raw clock cycles consumed
 *   - instructions        : retired instructions (cycles/insns = IPC)
 *   - cache-misses        : LLC (last-level cache) misses — show memory pressure
 *   - cache-references    : LLC accesses (miss rate = misses/references)
 *   - branch-misses       : mispredicted branches (pipeline flush cost)
 *   - page-faults         : SW page fault counter (cross-check vs eBPF)
 */
typedef struct {
    uint64_t cycles;
    uint64_t instructions;
    uint64_t cache_references;
    uint64_t cache_misses;
    uint64_t branch_misses;
    uint64_t page_faults_sw;   /* software event, matches kernel fault counter */
    int      available;        /* 0 if perf_event_open() failed (no root/cap) */
} perf_metrics_t;

/*
 * Internal: one open perf fd per hardware counter.
 * We keep them open across the benchmark loop and reset with PERF_EVENT_IOC_RESET.
 */
typedef struct {
    int fd_cycles;
    int fd_instructions;
    int fd_cache_refs;
    int fd_cache_misses;
    int fd_branch_misses;
    int fd_page_faults;
    int valid;
} perf_fds_t;
typedef struct {
    uint64_t latency_ns;
    struct ebpf_metrics ebpf;   /* combined parent + child metrics */
    perf_metrics_t perf;        /* hardware counters for this iteration */
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

    /* perf hardware counter averages */
    double mean_cycles;
    double mean_instructions;
    double mean_cache_refs;
    double mean_cache_misses;
    double mean_branch_misses;
    double mean_page_faults_sw;
    int    perf_available;
} result_t;

static tracer_ctx_t *g_tracer = NULL;

/* -------------------------------------------------------------------------
 * perf_event_open() helpers
 * ------------------------------------------------------------------------- */

/* Thin wrapper around the raw Linux syscall (no glibc wrapper exists). */
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                             int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/*
 * open_perf_counter() - open a single perf counter and return its fd.
 *
 * pid=0  → measure the calling process (our benchmark).
 * cpu=-1 → measure on whichever CPU the process runs (follows migration).
 * group_fd=-1 → standalone counter (not grouped with others).
 * PERF_FLAG_FD_CLOEXEC → close fd in child processes so we don't inherit it.
 */
static int open_perf_counter(uint32_t type, uint64_t config) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type           = type;
    attr.size           = sizeof(attr);
    attr.config         = config;
    attr.disabled       = 1;   /* start disabled; we enable right before the syscall */
    attr.exclude_kernel = 0;   /* count kernel events too — fork is mostly kernel work */
    attr.exclude_hv     = 1;   /* exclude hypervisor (not relevant on bare metal) */
    attr.inherit        = 1;   /* count events in child processes too */
    return (int)perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
}

/*
 * perf_open() - open all hardware counters for one benchmark run.
 *
 * Call this once before the iteration loop, not once per iteration,
 * to avoid the overhead of open()/close() inside the hot path.
 * Use PERF_EVENT_IOC_RESET to zero the counters before each iteration.
 */
static perf_fds_t perf_open(void) {
    perf_fds_t fds;
    memset(&fds, 0, sizeof(fds));
    fds.valid = 0;

    fds.fd_cycles        = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    fds.fd_instructions  = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
    fds.fd_cache_refs    = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES);
    fds.fd_cache_misses  = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
    fds.fd_branch_misses = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES);
    /* Page faults as a SW event — stays valid even when HW counters are unavailable */
    fds.fd_page_faults   = open_perf_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);

    if (fds.fd_cycles < 0) {
        /* HW counters failed (not root, or running in VM without PMU passthrough).
         * We still try to keep the SW page-fault counter which has no such restriction. */
        fprintf(stderr, "[perf] Warning: hardware counters unavailable "
                        "(not root, or guest VM without PMU). "
                        "SW page-fault counter only.\n");
        /* Close any that did open */
        if (fds.fd_instructions  >= 0) close(fds.fd_instructions);
        if (fds.fd_cache_refs    >= 0) close(fds.fd_cache_refs);
        if (fds.fd_cache_misses  >= 0) close(fds.fd_cache_misses);
        if (fds.fd_branch_misses >= 0) close(fds.fd_branch_misses);
        fds.fd_instructions = fds.fd_cache_refs =
        fds.fd_cache_misses = fds.fd_branch_misses = -1;
    }

    fds.valid = (fds.fd_page_faults >= 0) ? 1 : 0;
    return fds;
}

static void perf_close(perf_fds_t *fds) {
    if (!fds->valid) return;
    int *arr[] = { &fds->fd_cycles, &fds->fd_instructions, &fds->fd_cache_refs,
                   &fds->fd_cache_misses, &fds->fd_branch_misses, &fds->fd_page_faults };
    for (int i = 0; i < 6; i++) {
        if (*arr[i] >= 0) { close(*arr[i]); *arr[i] = -1; }
    }
    fds->valid = 0;
}

/*
 * Convenience: reset + enable all open counters.
 * Call this immediately before the fork/vfork/posix_spawn call.
 */
static void perf_reset_and_enable(const perf_fds_t *fds) {
    if (!fds->valid) return;
    int fdarr[] = { fds->fd_cycles, fds->fd_instructions, fds->fd_cache_refs,
                    fds->fd_cache_misses, fds->fd_branch_misses, fds->fd_page_faults };
    for (int i = 0; i < 6; i++) {
        if (fdarr[i] >= 0) {
            ioctl(fdarr[i], PERF_EVENT_IOC_RESET,  0);
            ioctl(fdarr[i], PERF_EVENT_IOC_ENABLE, 0);
        }
    }
}

/*
 * Disable counters and read values into perf_metrics_t.
 * Call this immediately after the syscall returns.
 */
static void perf_disable_and_read(const perf_fds_t *fds, perf_metrics_t *out) {
    memset(out, 0, sizeof(*out));
    if (!fds->valid) return;

    int fdarr[] = { fds->fd_cycles, fds->fd_instructions, fds->fd_cache_refs,
                    fds->fd_cache_misses, fds->fd_branch_misses, fds->fd_page_faults };
    for (int i = 0; i < 6; i++) {
        if (fdarr[i] >= 0) ioctl(fdarr[i], PERF_EVENT_IOC_DISABLE, 0);
    }

    uint64_t *fields[] = { &out->cycles, &out->instructions, &out->cache_references,
                           &out->cache_misses, &out->branch_misses, &out->page_faults_sw };
    for (int i = 0; i < 6; i++) {
        if (fdarr[i] >= 0)
            read(fdarr[i], fields[i], sizeof(uint64_t));
    }
    out->available = 1;
}

/* -------------------------------------------------------------------------
 * Memory availability check
 * ------------------------------------------------------------------------- */

/*
 * get_free_memory_gb() - read MemAvailable from /proc/meminfo.
 *
 * MemAvailable is a kernel estimate of how much memory is usable without
 * swapping. It's more accurate than MemFree because it accounts for
 * reclaimable caches.
 *
 * Returns available memory in GB, or 0 on parse failure.
 */
static size_t get_free_memory_gb(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    size_t kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemAvailable: %zu kB", &kb) == 1) break;
    }
    fclose(f);
    return kb / (1024 * 1024);   /* kB → GB */
}

/*
 * memory_size_is_safe() - return 1 if we can safely allocate size_gb.
 *
 * We require 80% headroom: allocating more than 80% of available memory
 * risks triggering the OOM killer mid-benchmark, which would corrupt results.
 * A 20% buffer accommodates kernel overhead and other processes.
 */
static int memory_size_is_safe(size_t size_gb) {
    size_t free_gb = get_free_memory_gb();
    if (free_gb == 0) return 1;   /* couldn't read — let it try and fail gracefully */
    return (size_gb * 10) <= (free_gb * 8);   /* size_gb <= free_gb * 0.8 */
}

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

    /* Aggregate perf hardware counters */
    double sum_cycles = 0, sum_insns = 0, sum_crefs = 0;
    double sum_cmiss = 0, sum_bmiss = 0, sum_pfsw = 0;
    int perf_ok = 0;
    for (int i = 0; i < count; i++) {
        if (data[i].perf.available) {
            sum_cycles += (double)data[i].perf.cycles;
            sum_insns  += (double)data[i].perf.instructions;
            sum_crefs  += (double)data[i].perf.cache_references;
            sum_cmiss  += (double)data[i].perf.cache_misses;
            sum_bmiss  += (double)data[i].perf.branch_misses;
            sum_pfsw   += (double)data[i].perf.page_faults_sw;
            perf_ok++;
        }
    }
    if (perf_ok > 0) {
        result->mean_cycles       = sum_cycles / perf_ok;
        result->mean_instructions = sum_insns  / perf_ok;
        result->mean_cache_refs   = sum_crefs  / perf_ok;
        result->mean_cache_misses = sum_cmiss  / perf_ok;
        result->mean_branch_misses = sum_bmiss / perf_ok;
        result->mean_page_faults_sw = sum_pfsw / perf_ok;
    }
    result->perf_available = (perf_ok > 0);
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
    perf_fds_t pfds = perf_open();
    if (!pfds.valid)
        LOGF("  [perf] Hardware counters unavailable for this run.\n");

    for (int i = 0; i < iterations; i++) {

        if (g_tracer) tracer_reset_metrics(g_tracer, parent_pid);
        perf_reset_and_enable(&pfds);

        uint64_t start = get_time_ns();
        pid_t child = fork();
        if (child < 0) { perror("fork failed"); perf_close(&pfds); return -1; }

        if (child == 0) {
            /* Child: exit immediately. _exit() skips C library cleanup,
             * which is safer and avoids any stdio buffer interference. */
            _exit(0);
        }

        uint64_t end = get_time_ns();
        perf_disable_and_read(&pfds, &data[i].perf);
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
    perf_close(&pfds);
    return 0;
}

int benchmark_vfork(iteration_data_t *data, int iterations, int parent_pid) {
    perf_fds_t pfds = perf_open();

    for (int i = 0; i < iterations; i++) {

        if (g_tracer) tracer_reset_metrics(g_tracer, parent_pid);
        perf_reset_and_enable(&pfds);

        uint64_t start = get_time_ns();
        pid_t child = vfork();
        if (child < 0) { perror("vfork failed"); perf_close(&pfds); return -1; }

        if (child == 0) {
            /* vfork child shares parent memory — parent is frozen until
             * we call _exit(). Must not touch any variables or call
             * any library functions. */
            _exit(0);
        }

        /* Parent resumes here only after child has called _exit() */
        uint64_t end = get_time_ns();
        perf_disable_and_read(&pfds, &data[i].perf);
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
    perf_close(&pfds);
    return 0;
}

int benchmark_posix_spawn(iteration_data_t *data, int iterations, int parent_pid) {
    char *argv[] = {"/bin/true", NULL};
    perf_fds_t pfds = perf_open();

    for (int i = 0; i < iterations; i++) {

        if (g_tracer) tracer_reset_metrics(g_tracer, parent_pid);
        perf_reset_and_enable(&pfds);

        pid_t child;
        uint64_t start = get_time_ns();
        int ret = posix_spawn(&child, "/bin/true", NULL, NULL, argv, environ);
        uint64_t end = get_time_ns();

        perf_disable_and_read(&pfds, &data[i].perf);

        if (ret != 0) {
            fprintf(stderr, "posix_spawn failed: %s\n", strerror(ret));
            perf_close(&pfds);
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
    perf_close(&pfds);
    return 0;
}

/* -------------------------------------------------------------------------
 * Benchmark runner
 * ------------------------------------------------------------------------- */
int run_benchmark(size_t memory_gb, int use_huge_pages, const char *method,
                  result_t *result) {

    /* Skip this configuration if it would exhaust available RAM.
     * This allows listing the full 1-16 GB range in MEMORY_SIZES even on
     * smaller machines — the benchmark degrades gracefully instead of OOM. */
    if (!memory_size_is_safe(memory_gb)) {
        size_t free_gb = get_free_memory_gb();
        LOGF("\n[SKIP] %zu GB > 80%% of available memory (%zu GB free). "
             "Skipping %s/%s.\n",
             memory_gb, free_gb, method,
             use_huge_pages ? "2MB" : "4KB");
        return -1;
    }

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
        if (result->perf_available) {
            double ipc = (result->mean_instructions > 0)
                       ? result->mean_cycles / result->mean_instructions : 0.0;
            double miss_rate = (result->mean_cache_refs > 0)
                       ? 100.0 * result->mean_cache_misses / result->mean_cache_refs : 0.0;
            LOGF("  HW Counters| Cycles: %10.0f  Insns: %10.0f  CPI: %.2f\n",
                 result->mean_cycles, result->mean_instructions, ipc);
            LOGF("             | CacheRefs: %8.0f  CacheMisses: %8.0f  MissRate: %.1f%%\n",
                 result->mean_cache_refs, result->mean_cache_misses, miss_rate);
            LOGF("             | BranchMisses: %6.0f  SW_PageFaults: %6.0f\n",
                 result->mean_branch_misses, result->mean_page_faults_sw);
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

    int has_perf = 0;
    for (int i = 0; i < count; i++) if (results[i].perf_available) { has_perf = 1; break; }

    fprintf(g_csv_file,
            "Memory_GB,Page_Size,Method,Mean_ms,StdDev_ms,P99_ms,Min_ms,Max_ms");
    if (has_ebpf)
        fprintf(g_csv_file,
                ",PF_User,PF_Kernel,PF_Total"
                ",TLB_Total,TLB_RemoteShootdown,TLB_LocalShootdown"
                ",TLB_LocalMM,TLB_RemoteIPI,TLB_TaskSwitch");
    if (has_perf)
        fprintf(g_csv_file,
                ",HW_Cycles,HW_Instructions,HW_CacheRefs,HW_CacheMisses"
                ",HW_BranchMisses,SW_PageFaults");
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
        if (has_perf)
            fprintf(g_csv_file, ",%.0f,%.0f,%.0f,%.0f,%.0f,%.0f",
                    r->mean_cycles, r->mean_instructions,
                    r->mean_cache_refs, r->mean_cache_misses,
                    r->mean_branch_misses, r->mean_page_faults_sw);
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

    LOGF("\n=== perf Hardware Counter Legend ===\n");
    LOGF("  HW_Cycles        - CPU clock cycles consumed by the syscall.\n");
    LOGF("  HW_Instructions  - Retired instructions (Cycles/Instructions = CPI).\n");
    LOGF("  HW_CacheRefs     - Last-level cache (LLC) accesses.\n");
    LOGF("  HW_CacheMisses   - LLC misses (MissRate = Misses/Refs * 100).\n");
    LOGF("  HW_BranchMisses  - Mispredicted branches (pipeline flush overhead).\n");
    LOGF("  SW_PageFaults    - Software page-fault event (cross-checks eBPF count).\n");
    LOGF("  Note: HW counters require root or CAP_PERFMON. SW_PageFaults works\n");
    LOGF("        without root on most kernels (perf_event_paranoid <= 2).\n");
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

    /* Report available memory so the user knows which sizes will be skipped */
    size_t free_gb = get_free_memory_gb();
    LOGF("Available system memory : ~%zu GB\n", free_gb);
    LOGF("Memory sizes configured : ");
    for (size_t i = 0; i < NUM_MEMORY_SIZES; i++) {
        int safe = memory_size_is_safe(MEMORY_SIZES[i]);
        LOGF("%zuGB(%s)%s", MEMORY_SIZES[i], safe ? "OK" : "SKIP",
             i + 1 < NUM_MEMORY_SIZES ? " " : "\n");
    }

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
    int total_tests = NUM_MEMORY_SIZES * 2 * 3;  /* mem_sizes × page_types × methods */

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
