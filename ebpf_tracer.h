#ifndef EBPF_TRACER_H
#define EBPF_TRACER_H

/*
 * ebpf_tracer.h - Userspace API for loading and querying our eBPF tracer.
 *
 * benchmark.c includes this and calls these functions to:
 *   1. Load the eBPF program into the kernel (tracer_init)
 *   2. Tell the tracer which PID to watch (tracer_watch_pid)
 *   3. Snapshot current counters before a benchmark call (tracer_snapshot)
 *   4. Compute the delta after the call (tracer_delta)
 *   5. Unload the eBPF program on exit (tracer_cleanup)
 */

#include "tracer.h"

/*
 * Opaque handle returned by tracer_init().
 * benchmark.c holds one of these for the lifetime of the program.
 */
typedef struct tracer_ctx tracer_ctx_t;

/*
 * tracer_init() - Load and attach the eBPF program into the kernel.
 *
 * Opens tracer.bpf.o (the compiled BPF object file), loads it into the
 * kernel's BPF virtual machine, and attaches to the three tracepoints.
 *
 * Returns: pointer to tracer context on success, NULL on failure.
 *
 * Must be called once at program start (before any benchmarks).
 * Requires root privileges (CAP_BPF or CAP_SYS_ADMIN).
 */
tracer_ctx_t *tracer_init(const char *bpf_obj_path);

/*
 * tracer_cleanup() - Detach and unload the eBPF program.
 *
 * Removes all tracepoint hooks from the kernel and frees memory.
 * Call this at program exit.
 */
void tracer_cleanup(tracer_ctx_t *ctx);

/*
 * tracer_watch_pid() - Register a PID to monitor.
 *
 * Adds `pid` to the watched_pids BPF map so kernel events from
 * this PID will be counted. Call this for the benchmark process PID
 * before starting benchmark iterations.
 *
 * Returns: 0 on success, -1 on failure.
 */
int tracer_watch_pid(tracer_ctx_t *ctx, int pid);

/*
 * tracer_unwatch_pid() - Stop monitoring a PID.
 *
 * Removes `pid` from the watched_pids map. Call this after benchmarks
 * for a given configuration are done.
 *
 * Returns: 0 on success, -1 on failure.
 */
int tracer_unwatch_pid(tracer_ctx_t *ctx, int pid);

/*
 * tracer_reset_metrics() - Zero out the counters for a PID.
 *
 * Call this before each benchmark iteration to get a clean starting
 * point. Without this, counters accumulate across iterations and you
 * can only compute totals, not per-iteration deltas.
 *
 * Returns: 0 on success, -1 on failure.
 */
int tracer_reset_metrics(tracer_ctx_t *ctx, int pid);

/*
 * tracer_read_metrics() - Read current counters for a PID.
 *
 * Copies the current ebpf_metrics struct from the BPF map into `out`.
 * Call this after a benchmark iteration to get the post-event counts.
 * Subtract pre-event counts to get the delta for that iteration.
 *
 * Returns: 0 on success, -1 on failure (e.g. PID not in map yet).
 */
int tracer_read_metrics(tracer_ctx_t *ctx, int pid, struct ebpf_metrics *out);

/*
 * tracer_is_available() - Check if eBPF tracing is usable on this system.
 *
 * Returns 1 if:
 *   - Running as root (or with CAP_BPF)
 *   - Kernel supports the required tracepoints
 *   - libbpf is available
 * Returns 0 otherwise. benchmark.c uses this to gracefully degrade to
 * timing-only mode if eBPF is not available.
 */
int tracer_is_available(void);

#endif /* EBPF_TRACER_H */