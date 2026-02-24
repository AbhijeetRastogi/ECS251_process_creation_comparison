#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "kprobe_tracer.h"

struct kprobe_ctx {
    struct bpf_object *obj;
    struct bpf_program *prog_copy_page_range;
    struct bpf_program *prog_copy_page_range_ret;
    struct bpf_program *prog_dup_mm;
    struct bpf_program *prog_dup_mm_ret;
    struct bpf_program *prog_fork_tp;
    struct bpf_program *prog_syscall_enter;
    struct bpf_link *link_copy_page_range;
    struct bpf_link *link_copy_page_range_ret;
    struct bpf_link *link_dup_mm;
    struct bpf_link *link_dup_mm_ret;
    struct bpf_link *link_fork_tp;
    struct bpf_link *link_syscall_enter;
    int metrics_map_fd;
    int watched_pids_fd;
    int timestamps_fd;
};

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    fprintf(stderr, "[kprobe] ");
    return vfprintf(stderr, format, args);
}

int kprobe_tracer_is_available(void) {
    if (geteuid() != 0) {
        fprintf(stderr, "[kprobe] Warning: not running as root.\n");
        return 0;
    }
    if (access("/sys/kernel/debug/kprobes", F_OK) != 0) {
        fprintf(stderr, "[kprobe] Warning: kprobes not available.\n");
        return 0;
    }
    return 1;
}

kprobe_ctx_t *kprobe_tracer_init(const char *bpf_obj_path) {
    libbpf_set_print(libbpf_print_fn);
    
    kprobe_ctx_t *ctx = calloc(1, sizeof(kprobe_ctx_t));
    if (!ctx) {
        perror("calloc kprobe_ctx");
        return NULL;
    }
    
    ctx->obj = bpf_object__open(bpf_obj_path);
    if (libbpf_get_error(ctx->obj)) {
        fprintf(stderr, "[kprobe] Failed to open BPF object '%s': %s\n",
                bpf_obj_path, strerror(errno));
        free(ctx);
        return NULL;
    }
    
    if (bpf_object__load(ctx->obj)) {
        fprintf(stderr, "[kprobe] Failed to load BPF object.\n");
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }
    
    ctx->prog_copy_page_range = bpf_object__find_program_by_name(
        ctx->obj, "kprobe_copy_page_range_entry");
    ctx->prog_copy_page_range_ret = bpf_object__find_program_by_name(
        ctx->obj, "kprobe_copy_page_range_exit");
    ctx->prog_dup_mm = bpf_object__find_program_by_name(
        ctx->obj, "kprobe_dup_mm_entry");
    ctx->prog_dup_mm_ret = bpf_object__find_program_by_name(
        ctx->obj, "kprobe_dup_mm_exit");
    ctx->prog_fork_tp = bpf_object__find_program_by_name(
        ctx->obj, "trace_sched_process_fork");
    ctx->prog_syscall_enter = bpf_object__find_program_by_name(
        ctx->obj, "trace_sys_enter");
    
    int attached = 0;
    
    if (ctx->prog_copy_page_range) {
        ctx->link_copy_page_range = bpf_program__attach(ctx->prog_copy_page_range);
        if (!libbpf_get_error(ctx->link_copy_page_range))
            attached++;
    }
    
    if (ctx->prog_copy_page_range_ret) {
        ctx->link_copy_page_range_ret = bpf_program__attach(ctx->prog_copy_page_range_ret);
        if (!libbpf_get_error(ctx->link_copy_page_range_ret))
            attached++;
    }
    
    if (ctx->prog_dup_mm) {
        ctx->link_dup_mm = bpf_program__attach(ctx->prog_dup_mm);
        if (!libbpf_get_error(ctx->link_dup_mm))
            attached++;
    }
    
    if (ctx->prog_dup_mm_ret) {
        ctx->link_dup_mm_ret = bpf_program__attach(ctx->prog_dup_mm_ret);
        if (!libbpf_get_error(ctx->link_dup_mm_ret))
            attached++;
    }
    
    if (ctx->prog_fork_tp) {
        ctx->link_fork_tp = bpf_program__attach(ctx->prog_fork_tp);
        if (!libbpf_get_error(ctx->link_fork_tp))
            attached++;
    }
    
    if (ctx->prog_syscall_enter) {
        ctx->link_syscall_enter = bpf_program__attach(ctx->prog_syscall_enter);
        if (!libbpf_get_error(ctx->link_syscall_enter))
            attached++;
    }
    
    struct bpf_map *metrics_map = bpf_object__find_map_by_name(
        ctx->obj, "kprobe_metrics_map");
    struct bpf_map *watched_map = bpf_object__find_map_by_name(
        ctx->obj, "watched_pids");
    
    if (!metrics_map || !watched_map) {
        fprintf(stderr, "[kprobe] Failed to find BPF maps.\n");
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }
    
    ctx->metrics_map_fd = bpf_map__fd(metrics_map);
    ctx->watched_pids_fd = bpf_map__fd(watched_map);
    
    fprintf(stderr, "[kprobe] Initialized. %d probes attached.\n", attached);
    return ctx;
}

void kprobe_tracer_cleanup(kprobe_ctx_t *ctx) {
    if (!ctx) return;
    
    if (ctx->link_copy_page_range) bpf_link__destroy(ctx->link_copy_page_range);
    if (ctx->link_copy_page_range_ret) bpf_link__destroy(ctx->link_copy_page_range_ret);
    if (ctx->link_dup_mm) bpf_link__destroy(ctx->link_dup_mm);
    if (ctx->link_dup_mm_ret) bpf_link__destroy(ctx->link_dup_mm_ret);
    if (ctx->link_fork_tp) bpf_link__destroy(ctx->link_fork_tp);
    if (ctx->link_syscall_enter) bpf_link__destroy(ctx->link_syscall_enter);
    
    if (ctx->obj) bpf_object__close(ctx->obj);
    free(ctx);
}

int kprobe_watch_pid(kprobe_ctx_t *ctx, int pid) {
    if (!ctx) return -1;
    __u32 key = (__u32)pid;
    __u8 val = 1;
    if (bpf_map_update_elem(ctx->watched_pids_fd, &key, &val, BPF_ANY))
        return -1;
    return 0;
}

int kprobe_unwatch_pid(kprobe_ctx_t *ctx, int pid) {
    if (!ctx) return -1;
    __u32 key = (__u32)pid;
    bpf_map_delete_elem(ctx->watched_pids_fd, &key);
    return 0;
}

int kprobe_reset_metrics(kprobe_ctx_t *ctx, int pid) {
    if (!ctx) return -1;
    __u32 key = (__u32)pid;
    struct kprobe_metrics zero = {0};
    if (bpf_map_update_elem(ctx->metrics_map_fd, &key, &zero, BPF_ANY))
        return -1;
    return 0;
}

int kprobe_read_metrics(kprobe_ctx_t *ctx, int pid, struct kprobe_metrics *out) {
    if (!ctx || !out) return -1;
    __u32 key = (__u32)pid;
    memset(out, 0, sizeof(*out));
    if (bpf_map_lookup_elem(ctx->metrics_map_fd, &key, out)) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    return 0;
}

void kprobe_print_metrics(const struct kprobe_metrics *m) {
    printf("  copy_page_range: %llu calls, %.3f ms\n",
           (unsigned long long)m->copy_page_range_calls,
           m->copy_page_range_ns / 1e6);
    printf("  dup_mm: %llu calls, %.3f ms\n",
           (unsigned long long)m->dup_mm_calls,
           m->dup_mm_ns / 1e6);
    printf("  syscalls: fork=%llu vfork=%llu clone=%llu\n",
           (unsigned long long)m->fork_calls,
           (unsigned long long)m->vfork_calls,
           (unsigned long long)m->clone_calls);
}
