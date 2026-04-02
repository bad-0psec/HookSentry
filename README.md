# HookSentry
HookSentry is a simple tool for inspecting system DLLs loaded into processes, looking for functions hooked from AV/EDR.

It scans for potential hooks in system libraries and provides detailed information about each hook it finds. The tool compares the in-memory image of each DLL with its on-disk version, identifies hooked functions, and prints disassembled code to help analyze the changes.

In addition to scanning one or more specific processes (or itself), HookSentry can perform a full scan of all active processes on the system. 

**The tool is compatible with x64 systems only.**

## Usage
```cmd
C:\Users\user\Desktop>.\HookSentry.exe -h

|_| _  _ | (~ _  _ _|_ _
| |(_)(_)|<_)(/_| | | |\/
                      /
V0.5.1

Usage: HookSentry.exe [-a|-p <targets>|-v|-d|-o <file>]
Options:
        -h, --help: Show this message
        -p, --pid <targets>: Comma-separated list of PIDs or process names
                             (e.g. -p 1234,notepad.exe,5678)
        -a, --all: Analyze all active processes
        -v, --verbose: Enable verbose output
        -d, --disass: Display disassembled code
        -o, --output <file>: Write all output to file
```

The `-p` option accepts a flexible comma-separated list mixing numeric PIDs and process names:
```cmd
HookSentry.exe -p 1234                           # single PID
HookSentry.exe -p 1234,5678,9012                 # multiple PIDs
HookSentry.exe -p notepad.exe                    # single process by name
HookSentry.exe -p notepad.exe,1234,explorer.exe  # mixed PIDs and names
```
When a process name is specified, all running instances matching that name will be scanned.

## Example (single process, verbose)
```cmd
C:\Users\user\Desktop>.\HookSentry.exe -v -d

|_| _  _ | (~ _  _ _|_ _
| |(_)(_)|<_)(/_| | | |\/
                      /
V0.5.1

[*] Selected current process.
---
[*] Working on process 1 of 1 with PID: 2120
[*] Working on: C:\Windows\SYSTEM32\ntdll.dll
        [+] C:\Windows\SYSTEM32\ntdll.dll!ZwWriteVirtualMemory HOOKED!
                --> Jump target: 0x7ff94f0f02f8 -> trampoline -> 0x7ff98c1c3cb0 @ C:\Program Files\EDR\Hooks.dll

                Function in memory:

                0x9DC20:        jmp             0x2005a0
                0x9DC25:        int3
                0x9DC26:        int3
                0x9DC27:        int3

                Function on disk:

                0x9DC20:        mov             r10, rcx
                0x9DC23:        mov             eax, 0x3a
                        

[...]

[*] Working on: C:\Windows\System32\ucrtbase.dll
[*] Working on: C:\Windows\SYSTEM32\VCRUNTIME140.dll

*** SUMMARY ***

[+] PID: 2120 - 139 hooks found
    C:\Windows\SYSTEM32\ntdll.dll: 86 hooks
    C:\Windows\System32\KERNEL32.DLL: 8 hooks
    C:\Windows\System32\KERNELBASE.dll: 45 hooks
  Hooking libraries:
    Hooks.dll hooks:
      - ntdll.dll!ZwWriteVirtualMemory
      - ntdll.dll!NtAllocateVirtualMemory
      - KERNEL32.DLL!CreateProcessW
      [...]
```

## Example (aggregate report, full scan)
When scanning multiple processes (`-a` or `-p` with multiple targets), an aggregate report is appended that groups results by hooking library:
```cmd
C:\Users\user\Desktop>.\HookSentry.exe -a

[...]

*** SUMMARY ***

[+] PID: 2120 - 139 hooks found
    C:\Windows\SYSTEM32\ntdll.dll: 86 hooks
    C:\Windows\System32\KERNEL32.DLL: 8 hooks
    C:\Windows\System32\KERNELBASE.dll: 45 hooks
  Hooking libraries:
    Hooks.dll hooks:
      - ntdll.dll!ZwWriteVirtualMemory
      - KERNEL32.DLL!CreateProcessW
      [...]

[+] PID: 4560 - 139 hooks found
    C:\Windows\SYSTEM32\ntdll.dll: 86 hooks
    C:\Windows\System32\KERNEL32.DLL: 8 hooks
    C:\Windows\System32\KERNELBASE.dll: 45 hooks
  Hooking libraries:
    Hooks.dll hooks:
      - ntdll.dll!ZwWriteVirtualMemory
      - KERNEL32.DLL!CreateProcessW
      [...]


*** AGGREGATE REPORT ***

Hooking library: C:\Program Files\EDR\Hooks.dll
  Injected into PIDs: 2120, 4560
  Hooked functions:
    - ntdll.dll!ZwWriteVirtualMemory
    - ntdll.dll!NtAllocateVirtualMemory
    - KERNEL32.DLL!CreateProcessW
    - KERNELBASE.dll!CreateProcessInternalW
    [...]
```
