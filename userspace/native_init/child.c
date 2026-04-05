#define NULL ((void *)0)

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long NTSTATUS;
typedef unsigned long long HANDLE;

#define STATUS_SUCCESS 0
#define PROCESS_BASIC_INFORMATION_CLASS 0

typedef struct {
    NTSTATUS Status;
    unsigned long long Information;
} IO_STATUS_BLOCK;

typedef struct {
    unsigned long long Reserved1;
    unsigned long long PebBaseAddress;
    unsigned long long Reserved2[2];
    unsigned long long UniqueProcessId;
    unsigned long long InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct {
    u32 Length;
    u32 MaximumLength;
    u32 Flags;
    u32 DebugFlags;
    unsigned long long ConsoleHandle;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    unsigned char Remaining[16];
} RTL_USER_PROCESS_PARAMETERS;

typedef struct {
    u8 Reserved[16];
    unsigned long long ImageBaseAddress;
    unsigned long long Ldr;
    RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
} PEB;

extern NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle,
    u32 ProcessInformationClass,
    void *ProcessInformation,
    u32 ProcessInformationLength,
    u32 *ReturnLength
);
extern NTSTATUS NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    void *ApcRoutine,
    void *ApcContext,
    IO_STATUS_BLOCK *IoStatusBlock,
    const void *Buffer,
    unsigned long long Length,
    void *ByteOffset,
    void *Key
);
extern NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

static HANDLE query_stdout(void) {
    PROCESS_BASIC_INFORMATION pbi;
    u32 ret_len = 0;
    NTSTATUS status = NtQueryInformationProcess(
        (HANDLE)-1,
        PROCESS_BASIC_INFORMATION_CLASS,
        &pbi,
        (u32)sizeof(pbi),
        &ret_len
    );
    if (status != STATUS_SUCCESS) {
        return 0;
    }
    PEB *peb = (PEB *)pbi.PebBaseAddress;
    return peb->ProcessParameters->StandardOutput;
}

static void write_console(HANDLE out, const char *text) {
    IO_STATUS_BLOCK iosb;
    u64 len = 0;
    while (text[len] != 0) {
        len++;
    }
    (void)NtWriteFile(out, 0, NULL, NULL, &iosb, text, len, NULL, NULL);
}

void start(void) {
    HANDLE out = query_stdout();
    write_console(out, "native child: started\r\n");
    write_console(out, "native child: exiting\r\n");
    NtTerminateProcess((HANDLE)-1, 0);
    for (;;) {}
}
