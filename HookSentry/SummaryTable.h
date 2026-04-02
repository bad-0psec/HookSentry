#pragma once
#include <windows.h>

typedef struct {
	CHAR FunctionName[256];
	WCHAR HookingLibrary[MAX_PATH];
} HOOK_ENTRY, * LPHOOK_ENTRY;

typedef struct {
	PWSTR DllFullPath;
	LPHOOK_ENTRY HookEntries;
	DWORD HookEntryCount;
} DLL_INFO, * LPDLL_INFO;

typedef struct {
	DWORD Pid;
	LPDLL_INFO DllInfos;
	DWORD DllsCount;
} SUMMARY_TABLE_ROW, * LPSUMMARY_TABLE_ROW;

typedef struct {
	LPSUMMARY_TABLE_ROW Rows;
	DWORD RowsCount;
} SUMMARY_TABLE, * LPSUMMARY_TABLE;

void InitSummaryTable(LPSUMMARY_TABLE lpSummaryTable);
void FreeSummaryTable(LPSUMMARY_TABLE lpSummaryTable);
LPSUMMARY_TABLE_ROW FindOrAddSummaryTableRow(LPSUMMARY_TABLE lpSummaryTable, DWORD dwPid);
LPDLL_INFO FindOrAddDllInfo(LPSUMMARY_TABLE_ROW lpRow, PWSTR pszDllFullPath);
BOOL AddHookEntry(LPDLL_INFO lpDllInfo, const char* functionName, const wchar_t* hookingLibrary);
DWORD GetRowTotalHooks(LPSUMMARY_TABLE_ROW lpRow);
void PrintFullTable(LPSUMMARY_TABLE lpSummaryTable);
void PrintAggregateReport(LPSUMMARY_TABLE lpSummaryTable);
