typedef unsigned long long u64;

extern void start(void);

volatile u64 InitRelocAnchorData = (u64)&start;
