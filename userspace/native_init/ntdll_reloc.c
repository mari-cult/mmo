typedef unsigned long long u64;

extern void NtClose(void);

__declspec(dllexport) u64 NtdllRelocAnchorData = (u64)&NtClose;
