#ifndef KPROBE_TRACER_H
#define KPROBE_TRACER_H

#include <stdint.h>

struct kprobe_metrics {
    uint64_t copy_page_range_calls;
    uint64_t copy_page_range_ns;
    uint64_t dup_mm_calls;
    uint64_t dup_mm_ns;
    uint64_t copy_pte_range_calls;
    uint64_t pte_entries_copied;
    uint64_t fork_calls;
    uint64_t vfork_calls;
    uint64_t clone_calls;
};

typedef struct kprobe_ctx kprobe_ctx_t;

int kprobe_tracer_is_available(void);
kprobe_ctx_t *kprobe_tracer_init(const char *bpf_obj_path);
void kprobe_tracer_cleanup(kprobe_ctx_t *ctx);
int kprobe_watch_pid(kprobe_ctx_t *ctx, int pid);
int kprobe_unwatch_pid(kprobe_ctx_t *ctx, int pid);
int kprobe_reset_metrics(kprobe_ctx_t *ctx, int pid);
int kprobe_read_metrics(kprobe_ctx_t *ctx, int pid, struct kprobe_metrics *out);
void kprobe_print_metrics(const struct kprobe_metrics *m);

#endif
