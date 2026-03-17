# eBPF Tracer Fix Report — 2026-03-16

## Bugs Found & Fixed

### Bug 1: posix_spawn child PID race condition
- **Root cause:** `tracer.bpf.c` had no `sched_process_fork` tracepoint handler. The child PID was only added to `watched_pids` from userspace *after* `posix_spawn()` returned — but by then the child had already forked, exec'd, and generated all its page faults and TLB events. Those events were invisible to the tracer.
- **Fix in `tracer.bpf.c`:** Added a `SEC("tracepoint/sched/sched_process_fork")` handler that:
  - Checks if the parent PID is in `watched_pids`
  - If so, inserts the child PID into `watched_pids` and pre-zeroes its `metrics_map` entry
  - This happens atomically in the kernel *before* the child runs its first instruction — no events are missed
- **Fix in `ebpf_tracer.c`:**
  - Added `prog_fork` / `link_fork` fields to `tracer_ctx`
  - `tracer_init()` finds and attaches `trace_sched_process_fork`
  - `tracer_cleanup()` destroys `link_fork`
  - Updated init log message to include the new tracepoint
- **Note:** Existing `tracer_watch_pid(child)` / `tracer_unwatch_pid(child)` calls in `benchmark.c` left unchanged — `watch_pid` is now a harmless no-op (child already in map), `unwatch_pid` still correctly cleans up

### Bug 2: BPF `metrics_map` exhaustion (silent event drops)
- **Root cause:** `metrics_map` has `max_entries=1024`. Each benchmark iteration created a child whose PID got an entry in `metrics_map`, but `tracer_unwatch_pid()` only removed from `watched_pids` — never from `metrics_map`. Over the run: 100 iterations x 3 methods x 3+ configs = 900+ stale entries. By config 4, the map hit 1024 and `get_or_create_metrics()` returned NULL, **silently dropping all events** for remaining configs.
- **Fix in `ebpf_tracer.c`:** Added `bpf_map_delete_elem(ctx->metrics_map_fd, &key)` to `tracer_unwatch_pid()` so child entries are cleaned up after their metrics are read.

### Fix 3: Memory safety threshold too conservative for 8GB configs
- **Root cause:** `memory_size_is_safe()` required `size_gb <= free_gb * 0.8`. On a 16 GB machine with ~9 GB `MemAvailable`, 8 GB configs were skipped (`8 > 9 * 0.8 = 7.2`). The low `MemAvailable` is not due to dual-boot (disk partitioning doesn't affect RAM) — it's normal Linux overhead: kernel, desktop, system services, and page caches consuming ~7 GB.
- **Fix in `benchmark.c`:** Relaxed threshold from 80% to 90% (`size_gb <= free_gb * 0.9`). 8 GB now passes (`8 <= 9 * 0.9 = 8.1`). 10% headroom (~900 MB) is sufficient since benchmark allocations are short-lived. Updated the SKIP log message to match.

## Files Changed

| File | What changed |
|------|-------------|
| `tracer.bpf.c` | Added `sched_process_fork_args` struct and `trace_sched_process_fork` BPF handler |
| `ebpf_tracer.c` | Added `prog_fork`/`link_fork` plumbing; `tracer_unwatch_pid()` now also deletes from `metrics_map` |
| `benchmark.c` | Relaxed memory safety threshold from 80% to 90% |

## Remaining Known Limitation

- **`TLB_RemoteShootdown` and `TLB_LocalShootdown` are always 0.** This is a structural limitation of PID-based filtering, not a code bug. Remote shootdowns fire on the *receiving* CPU under an unrelated PID — our filter never matches. `TLB_RemoteIPI` (0.3–2.6 per iteration) captures the *sending* side and is the correct proxy for cross-CPU TLB invalidation cost.

## Data Point Worth Flagging

- **fork at 4GB / 4KB pages** shows a superlinear latency jump: 2.79 ms mean (vs ~1.1 ms expected from linear extrapolation). This is real — the page table tree (~8 MB for 1M PTEs) exceeds L2 cache, causing 43% LLC miss rates. This config also has high variance (stddev 0.54 ms, P99 6.1 ms), so expect noisier results on repeated runs.
