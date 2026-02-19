/*
 * ebpf_tracer.c - Userspace side of our eBPF tracing system.
 *
 * This file uses libbpf to:
 *   1. Open and load tracer.bpf.o into the kernel's BPF VM
 *   2. Attach BPF programs to kernel tracepoints
 *   3. Read/write BPF maps to control which PIDs to watch
 *      and to retrieve collected metrics
 *
 * Think of this as the "control room" - tracer.bpf.c is the camera
 * inside the kernel, this file is the screen you watch in userspace.
 *
 * DEPENDENCIES: libbpf (apt install libbpf-dev)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* libbpf is the standard library for loading and interacting with BPF
 * programs from userspace. It handles the system calls, map file
 * descriptors, and ELF parsing of the .bpf.o object file. */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf_tracer.h"
#include "tracer.h"

/*
 * Internal context structure.
 * The public API uses tracer_ctx_t* (opaque pointer).
 * Only this file knows the real layout.
 */
struct tracer_ctx {
    struct bpf_object *obj;         /* handle to the loaded BPF object file  */

    /* BPF program handles (one per tracepoint) */
    struct bpf_program *prog_pf_user;    /* page_fault_user handler           */
    struct bpf_program *prog_pf_kernel;  /* page_fault_kernel handler         */
    struct bpf_program *prog_tlb;        /* tlb_flush handler                 */

    /* BPF link handles - represent the attachment to a tracepoint.
     * Destroying a link detaches the program from the tracepoint. */
    struct bpf_link *link_pf_user;
    struct bpf_link *link_pf_kernel;
    struct bpf_link *link_tlb;

    /* File descriptors for the two BPF maps.
     * We use these to read/write map entries from userspace. */
    int metrics_map_fd;     /* metrics_map: PID -> ebpf_metrics counters     */
    int watched_pids_fd;    /* watched_pids: PID -> presence flag            */
};

/* -------------------------------------------------------------------------
 * libbpf log callback
 * By default libbpf prints verbose errors. We redirect them to stderr
 * with a clear prefix so users know where the messages come from.
 * ------------------------------------------------------------------------- */
static int libbpf_print_fn(enum libbpf_print_level level,
                            const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0; /* suppress debug spam, only show warnings/errors */
    fprintf(stderr, "[libbpf] ");
    return vfprintf(stderr, format, args);
}

/* -------------------------------------------------------------------------
 * Public API implementation
 * ------------------------------------------------------------------------- */

int tracer_is_available(void) {
    /* Check 1: Must be root (UID 0) or have CAP_BPF */
    if (geteuid() != 0) {
        fprintf(stderr, "[tracer] Warning: not running as root, "
                        "eBPF tracing will be disabled.\n");
        return 0;
    }

    /* Check 2: Check that key tracepoints exist on this kernel */
    const char *required_tracepoints[] = {
        "/sys/kernel/debug/tracing/events/exceptions/page_fault_user",
        "/sys/kernel/debug/tracing/events/exceptions/page_fault_kernel",
        "/sys/kernel/debug/tracing/events/tlb/tlb_flush",
    };

    for (int i = 0; i < 3; i++) {
        if (access(required_tracepoints[i], F_OK) != 0) {
            fprintf(stderr, "[tracer] Warning: tracepoint not found: %s\n"
                            "         Kernel may not support this tracepoint.\n",
                            required_tracepoints[i]);
            return 0;
        }
    }

    return 1;
}

tracer_ctx_t *tracer_init(const char *bpf_obj_path) {
    /* Redirect libbpf's internal log messages through our callback */
    libbpf_set_print(libbpf_print_fn);

    /* Allocate our context */
    tracer_ctx_t *ctx = calloc(1, sizeof(tracer_ctx_t));
    if (!ctx) {
        perror("calloc tracer_ctx");
        return NULL;
    }

    /* ---- Step 1: Open the BPF object file ---- 
     * bpf_object__open() parses the ELF file (tracer.bpf.o) but does NOT
     * yet load anything into the kernel. It's like opening a book to read it,
     * not yet executing its instructions. */
    ctx->obj = bpf_object__open(bpf_obj_path);
    if (libbpf_get_error(ctx->obj)) {
        fprintf(stderr, "[tracer] Failed to open BPF object '%s': %s\n"
                        "         Did you compile tracer.bpf.c first?\n",
                        bpf_obj_path, strerror(errno));
        free(ctx);
        return NULL;
    }

    /* ---- Step 2: Load the BPF object into the kernel ----
     * bpf_object__load() verifies the BPF program (safety check),
     * creates the BPF maps in kernel memory, and loads the BPF bytecode
     * into the kernel's BPF virtual machine.
     * 
     * If this fails with "Operation not permitted", you need to run as root.
     * If it fails with "Invalid argument", the BPF verifier rejected it. */
    if (bpf_object__load(ctx->obj)) {
        fprintf(stderr, "[tracer] Failed to load BPF object into kernel.\n"
                        "         Common causes:\n"
                        "           - Not running as root\n"
                        "           - Kernel BPF support not enabled\n"
                        "           - BPF verifier rejected the program\n");
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    /* ---- Step 3: Get handles to the BPF programs ----
     * The names must match the function names in tracer.bpf.c. */
    ctx->prog_pf_user = bpf_object__find_program_by_name(
                            ctx->obj, "trace_page_fault_user");
    ctx->prog_pf_kernel = bpf_object__find_program_by_name(
                            ctx->obj, "trace_page_fault_kernel");
    ctx->prog_tlb = bpf_object__find_program_by_name(
                            ctx->obj, "trace_tlb_flush");

    if (!ctx->prog_pf_user || !ctx->prog_pf_kernel || !ctx->prog_tlb) {
        fprintf(stderr, "[tracer] Failed to find BPF programs in object.\n"
                        "         Check function names in tracer.bpf.c.\n");
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    /* ---- Step 4: Attach programs to tracepoints ----
     * bpf_program__attach() installs the BPF program as a hook on the
     * tracepoint specified in the SEC("tracepoint/...") annotation.
     * From this moment, every time the kernel fires that tracepoint,
     * our BPF function runs. */
    ctx->link_pf_user = bpf_program__attach(ctx->prog_pf_user);
    if (libbpf_get_error(ctx->link_pf_user)) {
        fprintf(stderr, "[tracer] Failed to attach page_fault_user probe.\n");
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    ctx->link_pf_kernel = bpf_program__attach(ctx->prog_pf_kernel);
    if (libbpf_get_error(ctx->link_pf_kernel)) {
        fprintf(stderr, "[tracer] Failed to attach page_fault_kernel probe.\n");
        bpf_link__destroy(ctx->link_pf_user);
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    ctx->link_tlb = bpf_program__attach(ctx->prog_tlb);
    if (libbpf_get_error(ctx->link_tlb)) {
        fprintf(stderr, "[tracer] Failed to attach tlb_flush probe.\n");
        bpf_link__destroy(ctx->link_pf_user);
        bpf_link__destroy(ctx->link_pf_kernel);
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    /* ---- Step 5: Get file descriptors for the BPF maps ----
     * The names must match the map names in tracer.bpf.c. */
    struct bpf_map *metrics_map = bpf_object__find_map_by_name(
                                      ctx->obj, "metrics_map");
    struct bpf_map *watched_map = bpf_object__find_map_by_name(
                                      ctx->obj, "watched_pids");

    if (!metrics_map || !watched_map) {
        fprintf(stderr, "[tracer] Failed to find BPF maps. "
                        "Check map names in tracer.bpf.c.\n");
        bpf_link__destroy(ctx->link_pf_user);
        bpf_link__destroy(ctx->link_pf_kernel);
        bpf_link__destroy(ctx->link_tlb);
        bpf_object__close(ctx->obj);
        free(ctx);
        return NULL;
    }

    ctx->metrics_map_fd = bpf_map__fd(metrics_map);
    ctx->watched_pids_fd = bpf_map__fd(watched_map);

    fprintf(stderr, "[tracer] eBPF tracer initialized successfully.\n"
                    "         Attached to: page_fault_user, "
                    "page_fault_kernel, tlb_flush\n");
    return ctx;
}

void tracer_cleanup(tracer_ctx_t *ctx) {
    if (!ctx) return;

    /* Destroying the links detaches the BPF programs from tracepoints */
    if (ctx->link_pf_user)   bpf_link__destroy(ctx->link_pf_user);
    if (ctx->link_pf_kernel) bpf_link__destroy(ctx->link_pf_kernel);
    if (ctx->link_tlb)       bpf_link__destroy(ctx->link_tlb);

    /* Closing the object unloads the BPF programs and maps from the kernel */
    if (ctx->obj) bpf_object__close(ctx->obj);

    free(ctx);
    fprintf(stderr, "[tracer] eBPF tracer cleaned up.\n");
}

int tracer_watch_pid(tracer_ctx_t *ctx, int pid) {
    if (!ctx) return -1;
    __u32 key = (__u32)pid;
    __u8  val = 1;
    /* BPF_ANY = insert or update. This adds the PID to our watch set. */
    if (bpf_map_update_elem(ctx->watched_pids_fd, &key, &val, BPF_ANY)) {
        fprintf(stderr, "[tracer] Failed to watch PID %d: %s\n",
                pid, strerror(errno));
        return -1;
    }
    return 0;
}

int tracer_unwatch_pid(tracer_ctx_t *ctx, int pid) {
    if (!ctx) return -1;
    __u32 key = (__u32)pid;
    if (bpf_map_delete_elem(ctx->watched_pids_fd, &key)) {
        /* Not finding the key is fine - it may not have been added */
        if (errno != ENOENT) {
            fprintf(stderr, "[tracer] Failed to unwatch PID %d: %s\n",
                    pid, strerror(errno));
            return -1;
        }
    }
    return 0;
}

int tracer_reset_metrics(tracer_ctx_t *ctx, int pid) {
    if (!ctx) return -1;
    __u32 key = (__u32)pid;
    struct ebpf_metrics zero = {0};
    /*
     * BPF_ANY = create or overwrite. Writing all-zeros resets the counters
     * so our next read gives us just the events from this iteration.
     */
    if (bpf_map_update_elem(ctx->metrics_map_fd, &key, &zero, BPF_ANY)) {
        fprintf(stderr, "[tracer] Failed to reset metrics for PID %d: %s\n",
                pid, strerror(errno));
        return -1;
    }
    return 0;
}

int tracer_read_metrics(tracer_ctx_t *ctx, int pid, struct ebpf_metrics *out) {
    if (!ctx || !out) return -1;
    __u32 key = (__u32)pid;
    memset(out, 0, sizeof(*out));
    /*
     * bpf_map_lookup_elem reads the value for this key from the BPF map.
     * If the PID has not generated any events yet, the key may not exist
     * and this will return -1 with errno=ENOENT. We treat that as all-zeros.
     */
    if (bpf_map_lookup_elem(ctx->metrics_map_fd, &key, out)) {
        if (errno == ENOENT) {
            /* No events recorded yet for this PID - that's valid, return zeros */
            return 0;
        }
        fprintf(stderr, "[tracer] Failed to read metrics for PID %d: %s\n",
                pid, strerror(errno));
        return -1;
    }
    return 0;
}