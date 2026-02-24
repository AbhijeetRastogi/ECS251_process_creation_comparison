// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct kprobe_metrics {
    __u64 copy_page_range_calls;
    __u64 copy_page_range_ns;
    __u64 dup_mm_calls;
    __u64 dup_mm_ns;
    __u64 copy_pte_range_calls;
    __u64 pte_entries_copied;
    __u64 fork_calls;
    __u64 vfork_calls;
    __u64 clone_calls;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} entry_timestamps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct kprobe_metrics);
} kprobe_metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

static __always_inline int is_watched(__u32 pid) {
    return bpf_map_lookup_elem(&watched_pids, &pid) != NULL;
}

static __always_inline struct kprobe_metrics *get_or_create_metrics(__u32 pid) {
    struct kprobe_metrics *m = bpf_map_lookup_elem(&kprobe_metrics_map, &pid);
    if (!m) {
        struct kprobe_metrics zero = {};
        bpf_map_update_elem(&kprobe_metrics_map, &pid, &zero, BPF_NOEXIST);
        m = bpf_map_lookup_elem(&kprobe_metrics_map, &pid);
    }
    return m;
}

static __always_inline void save_entry_time(__u32 pid) {
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &pid, &ts, BPF_ANY);
}

static __always_inline __u64 get_duration_ns(__u32 pid) {
    __u64 *entry_ts = bpf_map_lookup_elem(&entry_timestamps, &pid);
    if (!entry_ts)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now - *entry_ts;
    bpf_map_delete_elem(&entry_timestamps, &pid);
    return duration;
}

SEC("kprobe/copy_page_range")
int BPF_KPROBE(kprobe_copy_page_range_entry) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (!is_watched(pid))
        return 0;
    
    save_entry_time(pid);
    
    struct kprobe_metrics *m = get_or_create_metrics(pid);
    if (m) {
        __sync_fetch_and_add(&m->copy_page_range_calls, 1);
    }
    
    return 0;
}

SEC("kretprobe/copy_page_range")
int BPF_KRETPROBE(kprobe_copy_page_range_exit) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (!is_watched(pid))
        return 0;
    
    __u64 duration = get_duration_ns(pid);
    
    struct kprobe_metrics *m = get_or_create_metrics(pid);
    if (m && duration > 0) {
        __sync_fetch_and_add(&m->copy_page_range_ns, duration);
    }
    
    return 0;
}

SEC("kprobe/dup_mm")
int BPF_KPROBE(kprobe_dup_mm_entry) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (!is_watched(pid))
        return 0;
    
    __u32 key = pid + 0x80000000;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &key, &ts, BPF_ANY);
    
    struct kprobe_metrics *m = get_or_create_metrics(pid);
    if (m) {
        __sync_fetch_and_add(&m->dup_mm_calls, 1);
    }
    
    return 0;
}

SEC("kretprobe/dup_mm")
int BPF_KRETPROBE(kprobe_dup_mm_exit) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (!is_watched(pid))
        return 0;
    
    __u32 key = pid + 0x80000000;
    __u64 *entry_ts = bpf_map_lookup_elem(&entry_timestamps, &key);
    if (!entry_ts)
        return 0;
    
    __u64 duration = bpf_ktime_get_ns() - *entry_ts;
    bpf_map_delete_elem(&entry_timestamps, &key);
    
    struct kprobe_metrics *m = get_or_create_metrics(pid);
    if (m && duration > 0) {
        __sync_fetch_and_add(&m->dup_mm_ns, duration);
    }
    
    return 0;
}

struct sched_process_fork_args {
    __u64 pad;
    char parent_comm[16];
    __u32 parent_pid;
    char child_comm[16];
    __u32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct sched_process_fork_args *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;
    
    if (!is_watched(parent_pid))
        return 0;
    
    __u8 val = 1;
    bpf_map_update_elem(&watched_pids, &child_pid, &val, BPF_ANY);
    
    struct kprobe_metrics *m = get_or_create_metrics(parent_pid);
    if (m) {
        __sync_fetch_and_add(&m->fork_calls, 1);
    }
    
    get_or_create_metrics(child_pid);
    
    return 0;
}

#define SYS_CLONE  56
#define SYS_FORK   57
#define SYS_VFORK  58

struct syscall_enter_args {
    __u64 pad;
    long syscall_nr;
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct syscall_enter_args *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    
    if (!is_watched(pid))
        return 0;
    
    struct kprobe_metrics *m = get_or_create_metrics(pid);
    if (!m)
        return 0;
    
    switch (ctx->syscall_nr) {
    case SYS_FORK:
        __sync_fetch_and_add(&m->fork_calls, 1);
        break;
    case SYS_VFORK:
        __sync_fetch_and_add(&m->vfork_calls, 1);
        break;
    case SYS_CLONE:
        __sync_fetch_and_add(&m->clone_calls, 1);
        break;
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
