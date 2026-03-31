#pragma once
#include <windows.h>
#include <wchar.h>
#include "SummaryTable.h"

#define MAX_INSN_LEN 15
#define JMP_REL32 0xE9
#define JMP_IND_PREFIX 0xFF
#define JMP_IND_MODRM 0x25
#define MOV_RAX_IMM64 0x48
#define JMP_SHORT 0xEB

#define RVA2VA(TYPE, BASE, RVA) (TYPE)((ULONG_PTR)BASE + RVA)

#define print_verbose(verbose, ...) \
	do { \
		if(verbose) { \
			wprintf(__VA_ARGS__); \
		} \
	} while(0) \

typedef struct {
	PVOID BaseAddress;
	ULONG SizeOfImage;
	WCHAR FullDllName[MAX_PATH];
} MODULE_INFO, *LPMODULE_INFO;

typedef struct {
	LPMODULE_INFO Modules;
	DWORD Count;
} MODULE_MAP, *LPMODULE_MAP;

BOOL GetSystemDllPath(PWSTR buffer, DWORD bufferLen);
BOOL BuildModuleMap(HANDLE hProcess, LPMODULE_MAP moduleMap);
void FreeModuleMap(LPMODULE_MAP moduleMap);
LPCWSTR ResolveTargetModule(LPMODULE_MAP moduleMap, ULONG_PTR targetAddress);
BOOL SearchHooks(HANDLE hProcess, LPSUMMARY_TABLE table, BOOL verbose, BOOL printDisass);