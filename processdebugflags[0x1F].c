#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(__stdcall *native_process)(    // __stdcall == WINAPI
    HANDLE,           // ProcessHandle
    PROCESSINFOCLASS, // ProcessInformationClass,
    PVOID,            // ProcessInformation,
    ULONG,            // ProcessInformationLength,
    PULONG            // ReturnLength
);

native_process get_nt_process() {
    HMODULE dll_handle= GetModuleHandleA("ntdll.dll");
    if (dll_handle== NULL) {
        return NULL;
    }
    return (native_process)GetProcAddress(dll_handle, "NtQueryInformationProcess");
}

BOOL detect_debugger_flag() {
    HANDLE process_handle= GetCurrentProcess();
    PVOID flags_buffer= 0;
    PROCESSINFOCLASS process_debug_flags= (PROCESSINFOCLASS)0x1F;
    native_process NtQueryInformationProcess= get_nt_process();
    if (NtQueryInformationProcess== NULL) {
        return 0;
    }
    NtQueryInformationProcess(process_handle, process_debug_flags, &flags_buffer, sizeof(flags_buffer), NULL);
    printf("process debug flags : %p", flags_buffer);
    if (flags_buffer!= 0) {
        return 1;
    }
    return 0;
}

int main() {
    if (detect_debugger_flag()) {
        MessageBox(NULL, TEXT("no debugger"), TEXT("notice"), MB_ICONINFORMATION | MB_OK);
        return 0;
    }
    MessageBoxA(NULL, "debugger detected", "caution", MB_ICONWARNING | MB_OK);
    return 0;
}
