# To Do

- scx_cake style scheduler:
  > scx_cake is an experimental BPF CPU scheduler that adapts the network CAKE algorithm's DRR++ (Deficit Round Robin++) for CPU scheduling. Designed for gaming workloads on modern AMD and Intel hardware. 4-Class System — Tasks classified as GAME / NORMAL / HOG / BG by PELT utilization and game family detection. Zero Global Atomics — Per-CPU BSS arrays with MESI-guarded writes eliminate bus locking. 3-Gate select_cpu — prev_cpu idle → performance-ordered scan → kernel fallback → tunnel. Per-LLC DSQ Sharding — Eliminates cross-CCD lock contention on multi-chiplet CPUs. EEVDF-Inspired Weighting — Virtual runtime with sleep lag credit, nice scaling, and tiered DSQ ordering.
- Add PCI + virtio blk support, creating and loading a `crabfs` filesystem via virtio blk pci.
- Test against a Gentoo stage3 tarball in attempt to get bash to run.
