// SPDX-License-Identifier: GPL-2.0
/*
 * tracer.bpf.c - eBPF kernel-side tracing program.
 *
 * This program runs INSIDE the Linux kernel (in BPF virtual machine).
 * It attaches to two types of kernel tracepoints:
 *
 *   1. exceptions/page_fault_user   - fires on every user-space page fault
 *   2. exceptions/page_fault_kernel - fires on every kernel-space page fault
 *   3. tlb/tlb_flush                - fires on every TLB flush event
 *
 * For each event, we check if the current PID is in our "watched_pids" map.
 * If it is, we increment counters in the "metrics_map" for that PID.
 *
 * Userspace (ebpf_tracer.c) controls which PIDs are watched and reads
 * the counters before/after each fork/vfork/posix_spawn call.
 *
 * BUILD:
 *   clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
 *         -I/usr/include/x86_64-linux-gnu \
 *         -c tracer.bpf.c -o tracer.bpf.o
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * We cannot include tracer.h directly here because it uses uint64_t
 * which is not available in BPF kernel headers. We redefine the struct
 * using __u64 which IS available in BPF context. The layout is identical.
 */
struct ebpf_metrics {
    __u64 page_faults_user;
    __u64 page_faults_kernel;
    __u64 tlb_flush_task_switch;
    __u64 tlb_remote_shootdown;
    __u64 tlb_local_shootdown;
    __u64 tlb_local_mm;
    __u64 tlb_remote_ipi_sent;
    __u64 tlb_total;
};

/* -------------------------------------------------------------------------
 * BPF Maps
 * Maps are shared memory between the kernel BPF program and userspace.
 * Think of them as key-value stores that both sides can read and write.
 * ------------------------------------------------------------------------- */

/*
 * metrics_map: PID (u32) -> ebpf_metrics
 *
 * Stores running counters for each watched PID.
 * Userspace reads this map before and after each benchmark iteration
 * and calculates the difference (delta) as the per-iteration cost.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);               /* key   = PID                      */
    __type(value, struct ebpf_metrics); /* value = event counters           */
} metrics_map SEC(".maps");

/*
 * watched_pids: PID (u32) -> u8
 *
 * A set of PIDs we want to observe. If a PID is in this map, we count
 * its events. If not, we ignore it (to avoid noise from unrelated processes).
 *
 * Userspace adds the benchmark PID (and child PIDs) to this map before
 * running each test, and removes them after.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);               /* key   = PID                      */
    __type(value, __u8);                /* value = 1 (just a presence flag) */
} watched_pids SEC(".maps");

/* -------------------------------------------------------------------------
 * Tracepoint argument structs
 *
 * When the kernel fires a tracepoint, it passes a struct with the event
 * fields. We must define these structs manually to match the kernel's
 * tracepoint format (since we are not using vmlinux.h).
 *
 * The first 8 bytes of every tracepoint struct are "common fields"
 * (type, flags, preempt_count, pid) used internally by the tracing system.
 * After those come the event-specific fields.
 *
 * You can see the exact format for any tracepoint by reading:
 *   /sys/kernel/debug/tracing/events/<subsystem>/<event>/format
 * ------------------------------------------------------------------------- */

/* Format: /sys/kernel/debug/tracing/events/exceptions/page_fault_user/format */
struct page_fault_args {
    __u64 pad;              /* 8 bytes of common tracepoint header fields   */
    unsigned long address;  /* the faulting virtual memory address          */
    unsigned long ip;       /* instruction pointer (where the fault came from) */
    unsigned long error_code; /* why the fault occurred (missing page, etc) */
};

/*
 * Format: /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
 *
 * The common 8-byte header is followed by parent_comm, parent_pid,
 * child_comm, child_pid (matches the kernel tracepoint layout exactly).
 */
struct sched_process_fork_args {
    __u64  pad;               /* 8-byte common tracepoint header              */
    char   parent_comm[16];   /* offset 8  – parent task name (informational) */
    __u32  parent_pid;        /* offset 24 – parent PID                       */
    char   child_comm[16];    /* offset 28 – child task name  (informational) */
    __u32  child_pid;         /* offset 44 – child PID                        */
};

/* Format: /sys/kernel/debug/tracing/events/tlb/tlb_flush/format */
struct tlb_flush_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    int   reason;           /* why the TLB was flushed (see TLB_* defines)  */
    int   _pad;
    unsigned long address;  /* address range being flushed (0 = full flush) */
};

/* -------------------------------------------------------------------------
 * Helper functions
 * ------------------------------------------------------------------------- */

/*
 * Check if this PID is one we're monitoring.
 * Returns non-zero if the PID is in the watched_pids map.
 */
static __always_inline int is_watched(__u32 pid) {
    return bpf_map_lookup_elem(&watched_pids, &pid) != NULL;
}

/*
 * Get the metrics struct for a PID, creating it if it doesn't exist.
 * Returns NULL if the map is full (shouldn't happen with max_entries=1024).
 */
static __always_inline struct ebpf_metrics *get_or_create_metrics(__u32 pid) {
    struct ebpf_metrics *m = bpf_map_lookup_elem(&metrics_map, &pid);
    if (!m) {
        struct ebpf_metrics zero = {};
        bpf_map_update_elem(&metrics_map, &pid, &zero, BPF_NOEXIST);
        m = bpf_map_lookup_elem(&metrics_map, &pid);
    }
    return m;
}

/* -------------------------------------------------------------------------
 * Tracepoint handlers
 * These are the actual functions that run in the kernel when events fire.
 * SEC("tracepoint/...") tells the BPF loader which tracepoint to attach to.
 * ------------------------------------------------------------------------- */

/*
 * Fires when a user-space memory access causes a page fault.
 *
 * In the context of fork():
 *   - After fork(), child pages are marked Copy-on-Write (CoW).
 *   - When the child (or parent) writes to a CoW page, a page fault fires.
 *   - The kernel then makes a real copy of that page.
 *   - More page faults = more CoW copies = more overhead after fork.
 */
SEC("tracepoint/exceptions/page_fault_user")
int trace_page_fault_user(struct page_fault_args *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (!is_watched(pid))
        return 0;

    struct ebpf_metrics *m = get_or_create_metrics(pid);
    if (!m)
        return 0;

    __sync_fetch_and_add(&m->page_faults_user, 1);
    return 0;
}

/*
 * Fires when a kernel-mode memory access causes a page fault.
 *
 * In the context of fork():
 *   - The kernel itself faults when copying page table entries.
 *   - These kernel page faults represent the direct overhead of fork()
 *     copying the parent's memory mapping structures.
 */
SEC("tracepoint/exceptions/page_fault_kernel")
int trace_page_fault_kernel(struct page_fault_args *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (!is_watched(pid))
        return 0;

    struct ebpf_metrics *m = get_or_create_metrics(pid);
    if (!m)
        return 0;

    __sync_fetch_and_add(&m->page_faults_kernel, 1);
    return 0;
}

/*
 * Fires on every TLB (Translation Lookaside Buffer) flush event.
 *
 * The TLB is a CPU cache that speeds up memory address translation.
 * When fork() changes page ownership (for CoW), the TLB entries for
 * those pages become stale. The kernel must flush them across all CPU cores.
 *
 * The "shootdown" is when one CPU sends interrupts to ALL other CPUs
 * telling them to flush their TLB caches too. This is expensive because
 * it stalls every CPU core momentarily.
 *
 * We break down the total count by `reason` to distinguish:
 *   - Normal task-switch flushes (expected, baseline noise)
 *   - Remote shootdowns (the expensive cross-CPU flushes from fork)
 *   - Local flushes (this CPU flushing itself)
 */
SEC("tracepoint/tlb/tlb_flush")
int trace_tlb_flush(struct tlb_flush_args *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    if (!is_watched(pid))
        return 0;

    struct ebpf_metrics *m = get_or_create_metrics(pid);
    if (!m)
        return 0;

    /* Always increment the grand total */
    __sync_fetch_and_add(&m->tlb_total, 1);

    /* Increment the specific reason counter */
    switch (ctx->reason) {
        case 0: /* TLB_FLUSH_ON_TASK_SWITCH */
            __sync_fetch_and_add(&m->tlb_flush_task_switch, 1);
            break;
        case 1: /* TLB_REMOTE_SHOOTDOWN - the key metric for fork overhead */
            __sync_fetch_and_add(&m->tlb_remote_shootdown, 1);
            break;
        case 2: /* TLB_LOCAL_SHOOTDOWN */
            __sync_fetch_and_add(&m->tlb_local_shootdown, 1);
            break;
        case 3: /* TLB_LOCAL_MM_SHOOTDOWN */
            __sync_fetch_and_add(&m->tlb_local_mm, 1);
            break;
        case 4: /* TLB_REMOTE_SEND_IPI */
            __sync_fetch_and_add(&m->tlb_remote_ipi_sent, 1);
            break;
        default:
            break;
    }

    return 0;
}

/*
 * Fires in the kernel at the moment a new process is created via fork/vfork/
 * clone — before the child has run a single instruction.
 *
 * Problem this solves (posix_spawn race):
 *   posix_spawn() calls clone/vfork internally, then the child immediately
 *   exec()s.  All the interesting events (page faults during exec, TLB
 *   flushes) happen *inside* the child before userspace has a chance to call
 *   tracer_watch_pid() for the child PID.  By the time the benchmark does
 *   that, the child's work is already done and the events are lost.
 *
 *   By hooking sched_process_fork in the kernel we can add the child to
 *   watched_pids atomically at birth — before it runs — so we never miss
 *   an event.
 */
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct sched_process_fork_args *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid  = ctx->child_pid;

    /* Only propagate when the parent is already being watched */
    if (!is_watched(parent_pid))
        return 0;

    /* Add the child to the watch set so its events are captured from birth */
    __u8 val = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &val, BPF_ANY);

    /* Pre-create a zeroed metrics entry for the child so the first atomic
     * increment always hits an existing entry rather than racing with
     * get_or_create_metrics() across CPUs. */
    struct ebpf_metrics zero = {};
    bpf_map_update_elem(&metrics_map, &child_pid, &zero, BPF_NOEXIST);

    return 0;
}

/* Required license declaration - BPF programs must declare their license.
 * GPL is required to access certain kernel functions via BPF helpers. */
char LICENSE[] SEC("license") = "GPL";