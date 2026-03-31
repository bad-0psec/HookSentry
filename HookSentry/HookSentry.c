#include "HookSentry.h"
#include <winternl.h>
#include <stdio.h>

#ifdef _CS_ENABLED
#include "CsUtils.h"
#endif

#pragma comment(lib, "ntdll")

BOOL GetSystemDllPath(PWSTR buffer, DWORD bufferLen)
{
	UINT len = GetSystemDirectoryW(buffer, bufferLen);
	if (len == 0 || len >= bufferLen)
		return FALSE;
	return TRUE;
}

static BOOL IsHookInstruction(BYTE* code)
{
	if (code[0] == JMP_REL32)
		return TRUE;
	if (code[0] == JMP_IND_PREFIX && code[1] == JMP_IND_MODRM)
		return TRUE;
	if (code[0] == MOV_RAX_IMM64 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0)
		return TRUE;
	if (code[0] == JMP_SHORT)
		return TRUE;
	return FALSE;
}

static DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva)
{
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
	{
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;
		DWORD sectionAddress = sectionHeader->VirtualAddress;
		if (rva >= sectionAddress && rva < sectionAddress + sectionSize)
			return rva - sectionAddress + sectionHeader->PointerToRawData;
	}
	return 0;
}

BOOL BuildModuleMap(HANDLE hProcess, LPMODULE_MAP moduleMap)
{
	PEB peb;
	PEB_LDR_DATA ldr;
	LDR_DATA_TABLE_ENTRY ldrEntry;
	PROCESS_BASIC_INFORMATION processBasicInformation;

	moduleMap->Modules = NULL;
	moduleMap->Count = 0;

	if (NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), 0) != 0)
		return FALSE;

	if (!ReadProcessMemory(hProcess, processBasicInformation.PebBaseAddress, &peb, sizeof(PEB), NULL))
		return FALSE;

	if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL))
		return FALSE;

	if (!ReadProcessMemory(hProcess, ldr.Reserved2[1], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
		return FALSE;

	PVOID pFirstAddress = ldrEntry.Reserved1[0];

	while (1)
	{
		if (!ReadProcessMemory(hProcess, (PLDR_DATA_TABLE_ENTRY)ldrEntry.Reserved1[0], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
		{
			FreeModuleMap(moduleMap);
			return FALSE;
		}

		if (pFirstAddress == ldrEntry.Reserved1[0])
			break;

		if (ldrEntry.DllBase == NULL)
			continue;

		LPMODULE_INFO tmp = (LPMODULE_INFO)realloc(moduleMap->Modules, (moduleMap->Count + 1) * sizeof(MODULE_INFO));
		if (tmp == NULL)
		{
			FreeModuleMap(moduleMap);
			return FALSE;
		}
		moduleMap->Modules = tmp;

		MODULE_INFO* mod = &moduleMap->Modules[moduleMap->Count];
		mod->BaseAddress = ldrEntry.DllBase;
		mod->SizeOfImage = ldrEntry.Reserved3[1] ? (ULONG)(ULONG_PTR)ldrEntry.Reserved3[1] : 0;
		mod->FullDllName[0] = L'\0';

		if (ldrEntry.FullDllName.Length > 0 && ldrEntry.FullDllName.Buffer != NULL)
		{
			USHORT bytesToRead = ldrEntry.FullDllName.Length;
			if (bytesToRead > (MAX_PATH - 1) * sizeof(WCHAR))
				bytesToRead = (MAX_PATH - 1) * sizeof(WCHAR);

			if (ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, mod->FullDllName, bytesToRead, NULL))
				mod->FullDllName[bytesToRead / sizeof(WCHAR)] = L'\0';
			else
				mod->FullDllName[0] = L'\0';
		}

		moduleMap->Count++;
	}

	return TRUE;
}

void FreeModuleMap(LPMODULE_MAP moduleMap)
{
	if (moduleMap->Modules != NULL)
	{
		free(moduleMap->Modules);
		moduleMap->Modules = NULL;
	}
	moduleMap->Count = 0;
}

LPCWSTR ResolveTargetModule(LPMODULE_MAP moduleMap, ULONG_PTR targetAddress)
{
	for (DWORD i = 0; i < moduleMap->Count; i++)
	{
		ULONG_PTR base = (ULONG_PTR)moduleMap->Modules[i].BaseAddress;
		ULONG_PTR end = base + moduleMap->Modules[i].SizeOfImage;
		if (targetAddress >= base && targetAddress < end)
			return moduleMap->Modules[i].FullDllName;
	}
	return NULL;
}

/*
* Computes the absolute jump target address from the hook instruction bytes.
* mFunctionAddress is the in-memory virtual address where the hooked function starts.
* hProcess is needed for FF 25 (jmp [rip+disp32]) to dereference the pointer.
*/
static BOOL ResolveJumpTarget(BYTE* code, PVOID mFunctionAddress, HANDLE hProcess, ULONG_PTR* pTarget)
{
	if (code[0] == JMP_REL32)
	{
		// E9 xx xx xx xx  ->  target = address_of_next_insn + (signed)disp32
		INT32 disp = *(INT32*)(code + 1);
		*pTarget = (ULONG_PTR)mFunctionAddress + 5 + disp;
		return TRUE;
	}

	if (code[0] == JMP_IND_PREFIX && code[1] == JMP_IND_MODRM)
	{
		// FF 25 xx xx xx xx  ->  target = *[RIP + disp32]  (RIP = address_of_next_insn)
		INT32 disp = *(INT32*)(code + 2);
		ULONG_PTR ptrAddr = (ULONG_PTR)mFunctionAddress + 6 + disp;
		ULONG_PTR target = 0;
		if (!ReadProcessMemory(hProcess, (PVOID)ptrAddr, &target, sizeof(ULONG_PTR), NULL))
			return FALSE;
		*pTarget = target;
		return TRUE;
	}

	if (code[0] == MOV_RAX_IMM64 && code[1] == 0xB8)
	{
		// 48 B8 xx xx xx xx xx xx xx xx  FF E0  ->  target = imm64
		*pTarget = *(ULONG_PTR*)(code + 2);
		return TRUE;
	}

	if (code[0] == JMP_SHORT)
	{
		// EB xx  ->  target = address_of_next_insn + (signed)disp8
		INT8 disp = *(INT8*)(code + 1);
		*pTarget = (ULONG_PTR)mFunctionAddress + 2 + disp;
		return TRUE;
	}

	return FALSE;
}

/*
* When the initial jump target lands in unmapped memory (e.g. a trampoline stub
* allocated outside any known module), read the bytes at that address and try to
* decode one more jump to reach the real destination.
*/
static BOOL FollowTrampoline(HANDLE hProcess, ULONG_PTR trampolineAddr, ULONG_PTR* pFinalTarget)
{
	BYTE code[MAX_INSN_LEN];
	if (!ReadProcessMemory(hProcess, (PVOID)trampolineAddr, code, MAX_INSN_LEN, NULL))
		return FALSE;

	return ResolveJumpTarget(code, (PVOID)trampolineAddr, hProcess, pFinalTarget);
}

BOOL SearchHooks(HANDLE hProcess, LPSUMMARY_TABLE table, BOOL verbose, BOOL printDisass)
{
	PEB peb;
	PEB_LDR_DATA ldr;
	LDR_DATA_TABLE_ENTRY ldrEntry;
	PROCESS_BASIC_INFORMATION processBasicInformation;

	/*
	* Build a map of all loaded modules so we can resolve hook jump targets.
	*/
	MODULE_MAP moduleMap;
	if (!BuildModuleMap(hProcess, &moduleMap))
		return FALSE;

	/*
	* Gets basic information about the specified process.We use this to get the PEB base address.
	* Query '0' means ProcessBasicInformation.
	*
	* https://learn.microsoft.com/it-it/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
	*/
	if (NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &processBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), 0) != 0)
	{
		FreeModuleMap(&moduleMap);
		return FALSE;
	}

	/*
	* Reads PEB.
	*
	* https://learn.microsoft.com/it-it/windows/win32/api/winternl/ns-winternl-peb
	*/
	if (!ReadProcessMemory(hProcess, processBasicInformation.PebBaseAddress, &peb, sizeof(PEB), NULL))
	{
		FreeModuleMap(&moduleMap);
		return FALSE;
	}

	/*
	* PEB contains the address of LDR, which is a table containing information about
	* the the modules loaded for the process.
	*
	* https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	*/
	if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL))
	{
		FreeModuleMap(&moduleMap);
		return FALSE;
	}

	/*
	* _PEB_LDR_DATA is not fully documented by Microsoft. However, we know that
	* at offset 0x10 we find _LIST_ENTRY InLoadOrderModuleList which is "a doubly
	* linked list containing pointers to LDR_MODULE strucuture for previous and next
	* module in load order" (http://undocumented.ntinternals.net/).
	*
	* With ldr.Reserved2[1] we point to the first element of this list.
	*
	* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi_x/peb_ldr_data.htm
	*/
	if (!ReadProcessMemory(hProcess, ldr.Reserved2[1], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
	{
		FreeModuleMap(&moduleMap);
		return FALSE;
	}

	/*
	* We are saving the first address of the list because, since this is a circular list, we know to
	* have reached the end when we find it again.
	*/
	PVOID pFirstAddress = ldrEntry.Reserved1[0];

	/*
	* Start iterating through the modules in the InLoadOrderModuleList.
	*/
	while (1)
	{
		/*
		* Reserved1 is a pointers to _LIST_ENTRY InLoadOrderLinks which holds pointers to
		* the previous and next module in load order. We do this to move to next module in the list.
		*/
		if (!ReadProcessMemory(hProcess, (PLDR_DATA_TABLE_ENTRY)ldrEntry.Reserved1[0], &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL))
		{
			FreeModuleMap(&moduleMap);
			return FALSE;
		}

		if (pFirstAddress == ldrEntry.Reserved1[0])
			break;

		/*
		* Doing some acrobatics to read the DLL name stored as it is stored as _UNICODE_STRING.
		* Then we are going to make an infallible test to determine if we are examining a system
		* library or not
		*/
		PWSTR dllName = (PWSTR)malloc(ldrEntry.FullDllName.MaximumLength);
		if (dllName == NULL)
		{
			FreeModuleMap(&moduleMap);
			return FALSE;
		}
		if (!ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, dllName, ldrEntry.FullDllName.MaximumLength, NULL))
		{
			free(dllName);
			continue;
		}

		WCHAR systemDllPath[MAX_PATH];
		if (!GetSystemDllPath(systemDllPath, MAX_PATH))
		{
			free(dllName);
			FreeModuleMap(&moduleMap);
			return FALSE;
		}
		if (_wcsnicmp(dllName, systemDllPath, wcslen(systemDllPath)) != 0)
		{
			print_verbose(verbose, L"[*] %ls not a system library. skipped.\n", dllName);
			free(dllName);
			continue;
		}
		print_verbose(verbose, L"[*] Working on: %ls\n", dllName);

		/*
		* The next instructions are to open the DLL file on the disk with name = 'dllName'
		* and store its content in a memory buffer that is pointed to by
		* the variable 'pDllImageBase'.
		*/
		HANDLE hFile = CreateFileW(dllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hFile || hFile == INVALID_HANDLE_VALUE)
		{
			print_verbose(verbose, L"[!] Failed to open file: %ls. Error: %lu\n", dllName, GetLastError());
			free(dllName);
			continue; // Skip this DLL and move to the next one
		}
		DWORD dwFileLen = GetFileSize(hFile, NULL);
		if (dwFileLen == INVALID_FILE_SIZE)
		{
			print_verbose(verbose, L"[!] Failed to get file size: %ls. Error: %lu\n", dllName, GetLastError());
			free(dllName);
			CloseHandle(hFile);
			continue;  // Skip this DLL and move to the next one
		}
		PVOID pDllImageBase = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);
		if (pDllImageBase == NULL)
		{
			print_verbose(verbose, L"[!] FATAL ERROR. Out of memory\n");
			free(dllName);
			CloseHandle(hFile);
			FreeModuleMap(&moduleMap);
			return FALSE;
		}
		DWORD dwNumberOfBytesRead;
		if (!ReadFile(hFile, pDllImageBase, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead)
		{
			print_verbose(verbose, L"[!] Failed to read file %ls. Error: %lu\n", dllName, GetLastError());
			free(dllName);
			CloseHandle(hFile);
			HeapFree(GetProcessHeap(), 0, pDllImageBase);
			FreeModuleMap(&moduleMap);
			return FALSE;
		}
		CloseHandle(hFile);

		/*
		* We now read through PE32+ headers.
		* Our goal is the export directory, which contains the names of functions
		* and their offsets.
		*/

		// DOS Header
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pDllImageBase;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			print_verbose(verbose, L"[!] %ls is not a valid PE file (bad DOS signature). Skipping.\n", dllName);
			free(dllName);
			HeapFree(GetProcessHeap(), 0, pDllImageBase);
			continue;
		}
		// NT Header
		PIMAGE_NT_HEADERS ntHeader = RVA2VA(PIMAGE_NT_HEADERS, pDllImageBase, dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			print_verbose(verbose, L"[!] %ls is not a valid PE file (bad NT signature). Skipping.\n", dllName);
			free(dllName);
			HeapFree(GetProcessHeap(), 0, pDllImageBase);
			continue;
		}
		// Data Directory
		PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory;
		// Export Table
		DWORD exportTableVA = dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (exportTableVA == 0)
		{
			print_verbose(verbose, L"[*] %ls has no export directory. Skipping.\n", dllName);
			free(dllName);
			HeapFree(GetProcessHeap(), 0, pDllImageBase);
			continue;
		}
		DWORD exportTableFileOffset = RvaToFileOffset(ntHeader, exportTableVA);
		if (exportTableFileOffset == 0)
		{
			print_verbose(verbose, L"[!] %ls has an invalid export directory RVA. Skipping.\n", dllName);
			free(dllName);
			HeapFree(GetProcessHeap(), 0, pDllImageBase);
			continue;
		}
		// Export Directory
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, pDllImageBase, exportTableFileOffset);

		// Read number of names
		DWORD numberOfNames = exportDirectory->NumberOfNames;
		// Get Functions addresses array
		PDWORD iFunctions = RVA2VA(PDWORD, pDllImageBase, RvaToFileOffset(ntHeader, exportDirectory->AddressOfFunctions));
		// Get Function names array
		PDWORD iNames = RVA2VA(PDWORD, pDllImageBase, RvaToFileOffset(ntHeader, exportDirectory->AddressOfNames));
		// Get Function ordinals array
		PWORD iOrdinals = RVA2VA(PWORD, pDllImageBase, RvaToFileOffset(ntHeader, exportDirectory->AddressOfNameOrdinals));

		/*
		*  Finally, we can go through all the functions in the export directory and look for those damn hooks!
		*/
		DWORD hookCount = 0;
		while (numberOfNames > 0)
		{
			PCHAR functionName = RVA2VA(PCHAR, pDllImageBase, RvaToFileOffset(ntHeader, iNames[numberOfNames - 1]));
			DWORD vaFunctionAddress = iFunctions[iOrdinals[numberOfNames - 1]];

			/*
			* mFunctionAddress holds the address of the function that belongs to the in-memory module that has been loaded by hProcess.
			* iFunctionAddress holds the address of the function that belongs to the DLL that has been read from disk.
			*/
			PVOID mFunctionAddress = RVA2VA(PVOID, ldrEntry.DllBase, vaFunctionAddress);
			PVOID iFunctionAddress = RVA2VA(PVOID, pDllImageBase, RvaToFileOffset(ntHeader, vaFunctionAddress));

			BYTE mFunctionContent[MAX_INSN_LEN];
			if (!ReadProcessMemory(hProcess, mFunctionAddress, mFunctionContent, MAX_INSN_LEN, NULL)) {
				print_verbose(verbose, L"[!] Failed to read memory for function %hs at %p. Skipping.\n", functionName, mFunctionAddress);
				numberOfNames--;
				continue;
			}

			/*
			* FIRST CHECK - functions should be exactly the same.
			*/
			if (memcmp(mFunctionContent, iFunctionAddress, MAX_INSN_LEN) != 0)
			{
				/*
				* SECOND CHECK - is there a hook-like instruction at the start of the in-memory function?
				*/
				if (!IsHookInstruction(mFunctionContent)) {
					numberOfNames--;
					continue;
				}
				/*
				* Resolve jump target to filter out intra-module jumps (false positives).
				* Legitimate optimizations like CFG dispatch, import forwarding, and SSE2
				* dispatched math functions use short jumps within the same module.
				*
				* If the initial target lands outside any known module (trampoline stub),
				* follow one more jump to try to reach the real destination.
				*/
				ULONG_PTR jumpTarget = 0;
				ULONG_PTR finalTarget = 0;
				BOOL targetResolved = ResolveJumpTarget(mFunctionContent, mFunctionAddress, hProcess, &jumpTarget);
				BOOL trampolineFollowed = FALSE;
				LPCWSTR targetModuleName = NULL;

				if (targetResolved)
				{
					targetModuleName = ResolveTargetModule(&moduleMap, jumpTarget);

					if (targetModuleName == NULL)
					{
						/* Target is outside any known module - likely a trampoline stub */
						if (FollowTrampoline(hProcess, jumpTarget, &finalTarget))
						{
							trampolineFollowed = TRUE;
							targetModuleName = ResolveTargetModule(&moduleMap, finalTarget);
						}
					}

					if (targetModuleName != NULL && _wcsicmp(targetModuleName, dllName) == 0)
					{
						/* Jump stays within the same module - not a real hook */
						numberOfNames--;
						continue;
					}
				}

				hookCount++;

				wprintf(L"\t[+] Function %ls!%hs HOOKED!\n", dllName, functionName);
				if (targetResolved)
				{
					if (trampolineFollowed)
					{
						if (targetModuleName != NULL)
							wprintf(L"\t\t--> Jump target: 0x%llx -> trampoline -> 0x%llx @ %ls\n",
								(unsigned long long)jumpTarget, (unsigned long long)finalTarget, targetModuleName);
						else
							wprintf(L"\t\t--> Jump target: 0x%llx -> trampoline -> 0x%llx @ <unknown module>\n",
								(unsigned long long)jumpTarget, (unsigned long long)finalTarget);
					}
					else
					{
						if (targetModuleName != NULL)
							wprintf(L"\t\t--> Jump target: 0x%llx @ %ls\n", (unsigned long long)jumpTarget, targetModuleName);
						else
							wprintf(L"\t\t--> Jump target: 0x%llx @ <unknown module>\n", (unsigned long long)jumpTarget);
					}
				}

#ifdef _CS_ENABLED
				if (printDisass)
				{
					wprintf(L"\n\t\tFunction in memory:\n\n");
					PrintDisasm(mFunctionAddress, MAX_INSN_LEN, vaFunctionAddress);
					wprintf(L"\n\t\tFunction on disk:\n\n");
					PrintDisasm(iFunctionAddress, MAX_INSN_LEN, vaFunctionAddress);
					wprintf(L"\n");
				}
#endif
			}
			numberOfNames--;
		}

		if (table != NULL && hookCount > 0) {
			LPSUMMARY_TABLE_ROW row = AddSummaryTableRow(table, GetProcessId(hProcess));
			if (row == NULL) {
				wprintf(L"[!!!] out of memory\n");
				free(dllName);
				HeapFree(GetProcessHeap(), 0, pDllImageBase);
				FreeModuleMap(&moduleMap);
				return FALSE;
			}
			if (!AddSummaryTableRowInfo(row, dllName, hookCount)) {
				wprintf(L"[!!!] out of memory\n");
				free(dllName);
				HeapFree(GetProcessHeap(), 0, pDllImageBase);
				FreeModuleMap(&moduleMap);
				return FALSE;
			}
		}

		free(dllName);
		HeapFree(GetProcessHeap(), 0, pDllImageBase);
	}

	FreeModuleMap(&moduleMap);
	return TRUE;
}