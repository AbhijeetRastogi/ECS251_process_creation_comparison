# CoW Fault Analysis Report — 2026-03-16

## Why CoW Faults Benefit the Study

- Without `fork_cow`, the benchmark only measures fork's **page table copy** cost — the child exits immediately, showing a flat ~12 page faults regardless of memory size. This makes fork look cheap on memory work.
- With `fork_cow`, we expose fork's **deferred cost** — the actual page copies that CoW delays until a write happens. Page faults scale from ~12 to hundreds of thousands, proving that fork doesn't avoid the copy, it just hides it.
- This strengthens the case for `posix_spawn`/`vfork`: fork's true cost is far worse than the setup latency alone suggests.

## How fork_cow Works

- Parent allocates and touches N GB of memory (all pages resident)
- Parent calls `fork()` — kernel copies page tables, marks all pages read-only (CoW)
- **Child writes 1 byte per page** across the entire buffer (`volatile` write, stride = page size)
- Each write triggers a **user page fault** — kernel copies the shared page, gives the child a private copy
- Timer includes both the fork syscall AND all child CoW writes (`waitpid` before stopping clock)
- eBPF tracer captures every page fault and TLB event during this process

## Fixes Added for fork_cow

- **`benchmark.c`**: Added `benchmark_fork_cow()` function accepting `mem`, `mem_bytes`, and `page_size` from `run_benchmark()`. Child writes every page before `_exit()`. Registered as 4th method `"fork_cow"`.
- **`visualize_results.py`**:
  - Graphs 01–07 filtered to fork/vfork/posix_spawn only (via `base_methods()`) so fork_cow's massive numbers don't crush the scale
  - Graph 08 (summary table) keeps all 4 methods
  - Added 4 dedicated fork_cow analysis graphs (09–12)
  - Added orange colour (`#E67E22`) for fork_cow across all graphs

## Analysis Graphs 09–12

### Graph 09 — CoW Page Fault Scaling
- Compares total page faults: fork (flat ~12) vs fork_cow (scales with memory)
- Log Y-axis to show both on the same plot
- **Expected**: fork_cow at 4 GB / 4KB ≈ 1,048,576 faults (one per page); fork stays at ~12
- **Insight**: Proves fork's constant page fault count is syscall overhead, not memory work — the real memory cost is entirely deferred

### Graph 10 — fork vs fork_cow Latency Comparison
- Side-by-side bars at each memory size, with dashed arrows showing the delta
- **Expected**: fork_cow latency >> fork latency, gap grows with memory
- **Insight**: The arrow annotations quantify exactly how many ms of latency fork hides behind CoW — this is the cost that hits later when the process actually uses its memory

### Graph 11 — CoW Cost Breakdown (Setup vs Deferred)
- Stacked bar decomposing fork_cow latency into red (setup = fork page table copy) and orange (CoW = deferred page copies)
- Labels show total ms and % that is CoW
- **Expected**: At large memory sizes, CoW dominates (>90% of total cost); setup is a small fraction
- **Insight**: Directly shows that fork's "fast" page table copy is only a small part of the real cost — the bulk of work is hidden and paid later

### Graph 12 — fork_cow Huge Page Benefit
- Left panel: fork_cow latency with 4KB vs 2MB pages at each memory size
- Right panel: speedup ratio (4KB latency ÷ 2MB latency)
- **Expected**: Significant speedup (potentially 5–10×+) because 2MB pages mean 512× fewer CoW copies
- **Insight**: Huge pages matter far more for CoW-heavy workloads than for fork setup alone (where graph 03 showed ~1× for small sizes). This is the strongest argument for huge pages in fork-heavy applications that write to memory post-fork
