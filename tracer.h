#ifndef TRACER_H
#define TRACER_H

#include <stdint.h>

/*
 * tracer.h - Shared definitions between the eBPF kernel program (tracer.bpf.c)
 *            and the userspace loader (ebpf_tracer.c / benchmark.c).
 *
 * Both sides include this file. The kernel side uses BPF types (__u64 etc),
 * the userspace side uses stdint types (uint64_t etc). They are the same
 * size, so the struct layout is identical in both contexts.
 */

/*
 * TLB flush reason codes as defined in the Linux kernel.
 * These are the values the tlb/tlb_flush tracepoint puts in its `reason` field.
 *
 *  TLB_FLUSH_ON_TASK_SWITCH  - CPU is switching to a different task/process
 *  TLB_REMOTE_SHOOTDOWN      - another CPU is telling this CPU to flush (the
 *                              "shootdown" we care most about in fork())
 *  TLB_LOCAL_SHOOTDOWN       - this CPU is flushing its own TLB
 *  TLB_LOCAL_MM_SHOOTDOWN    - flushing TLB for a whole memory descriptor (mm)
 *  TLB_REMOTE_SEND_IPI       - inter-processor interrupt sent to remote CPUs
 *                              to request a TLB flush (the *sending* side)
 */
#define TLB_FLUSH_ON_TASK_SWITCH  0
#define TLB_REMOTE_SHOOTDOWN      1
#define TLB_LOCAL_SHOOTDOWN       2
#define TLB_LOCAL_MM_SHOOTDOWN    3
#define TLB_REMOTE_SEND_IPI       4

/*
 * Per-PID kernel event counters collected by our eBPF probes.
 * One of these structs is stored per PID in the BPF hash map.
 * Userspace reads two snapshots (before/after each fork call)
 * and subtracts them to get per-iteration deltas.
 */
struct ebpf_metrics {
    /* Page fault counters ----------------------------------------------- */
    uint64_t page_faults_user;      /* faults from user-space access        */
    uint64_t page_faults_kernel;    /* faults from kernel-space access      */

    /* TLB flush counters (broken down by reason) ------------------------- */
    uint64_t tlb_flush_task_switch; /* flush on context switch              */
    uint64_t tlb_remote_shootdown;  /* remote CPU ordered to flush TLB      */
    uint64_t tlb_local_shootdown;   /* this CPU flushing its own TLB        */
    uint64_t tlb_local_mm;          /* full mm (address space) TLB flush    */
    uint64_t tlb_remote_ipi_sent;   /* IPI sent to ask remote CPU to flush  */
    uint64_t tlb_total;             /* grand total of all TLB flush events  */
};

/*
 * Per-iteration result combining timing (from benchmark.c) and
 * eBPF kernel metrics (from tracer).
 */
struct iteration_result {
    uint64_t latency_ns;            /* wall-clock time for this iteration   */
    struct ebpf_metrics metrics;    /* kernel events during this iteration  */
};

/*
 * Aggregated statistics for one complete benchmark configuration
 * (e.g. fork + 1GB + 4KB pages, 100 iterations).
 */
struct extended_stats {
    /* Timing stats */
    double mean_ns;
    double stddev_ns;
    double percentile_99_ns;
    double min_ns;
    double max_ns;

    /* eBPF metric means (averaged over all iterations) */
    double mean_page_faults_user;
    double mean_page_faults_kernel;
    double mean_tlb_total;
    double mean_tlb_remote_shootdown;
    double mean_tlb_local_shootdown;
    double mean_tlb_local_mm;
    double mean_tlb_remote_ipi_sent;
    double mean_tlb_task_switch;
};

#endif /* TRACER_H */