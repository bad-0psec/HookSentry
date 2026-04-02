#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include "SummaryTable.h"

static const wchar_t* GetFileNameFromPath(const wchar_t* path)
{
	const wchar_t* name = wcsrchr(path, L'\\');
	return name ? name + 1 : path;
}

void InitSummaryTable(LPSUMMARY_TABLE lpSummaryTable)
{
	lpSummaryTable->Rows = NULL;
	lpSummaryTable->RowsCount = 0;
}

void FreeSummaryTable(LPSUMMARY_TABLE lpSummaryTable)
{
	if (lpSummaryTable->Rows == NULL)
		return;

	for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
	{
		LPSUMMARY_TABLE_ROW row = &lpSummaryTable->Rows[i];
		for (DWORD j = 0; j < row->DllsCount; j++)
		{
			free(row->DllInfos[j].DllFullPath);
			free(row->DllInfos[j].HookEntries);
		}
		free(row->DllInfos);
	}

	free(lpSummaryTable->Rows);
	lpSummaryTable->Rows = NULL;
	lpSummaryTable->RowsCount = 0;
}

LPSUMMARY_TABLE_ROW FindOrAddSummaryTableRow(LPSUMMARY_TABLE lpSummaryTable, DWORD dwPid)
{
	for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
	{
		if (lpSummaryTable->Rows[i].Pid == dwPid)
			return &lpSummaryTable->Rows[i];
	}

	LPSUMMARY_TABLE_ROW tmp = (LPSUMMARY_TABLE_ROW)realloc(lpSummaryTable->Rows, (lpSummaryTable->RowsCount + 1) * sizeof(SUMMARY_TABLE_ROW));
	if (tmp == NULL)
		return NULL;
	lpSummaryTable->Rows = tmp;

	LPSUMMARY_TABLE_ROW newRow = &lpSummaryTable->Rows[lpSummaryTable->RowsCount];
	newRow->Pid = dwPid;
	newRow->DllsCount = 0;
	newRow->DllInfos = NULL;

	lpSummaryTable->RowsCount++;
	return newRow;
}

LPDLL_INFO FindOrAddDllInfo(LPSUMMARY_TABLE_ROW lpRow, PWSTR pszDllFullPath)
{
	for (DWORD i = 0; i < lpRow->DllsCount; i++)
	{
		if (_wcsicmp(lpRow->DllInfos[i].DllFullPath, pszDllFullPath) == 0)
			return &lpRow->DllInfos[i];
	}

	LPDLL_INFO tmp = (LPDLL_INFO)realloc(lpRow->DllInfos, (lpRow->DllsCount + 1) * sizeof(DLL_INFO));
	if (tmp == NULL)
		return NULL;
	lpRow->DllInfos = tmp;

	LPDLL_INFO newDll = &lpRow->DllInfos[lpRow->DllsCount];
	newDll->DllFullPath = _wcsdup(pszDllFullPath);
	if (newDll->DllFullPath == NULL)
		return NULL;
	newDll->HookEntries = NULL;
	newDll->HookEntryCount = 0;

	lpRow->DllsCount++;
	return newDll;
}

BOOL AddHookEntry(LPDLL_INFO lpDllInfo, const char* functionName, const wchar_t* hookingLibrary)
{
	LPHOOK_ENTRY tmp = (LPHOOK_ENTRY)realloc(lpDllInfo->HookEntries, (lpDllInfo->HookEntryCount + 1) * sizeof(HOOK_ENTRY));
	if (tmp == NULL)
		return FALSE;
	lpDllInfo->HookEntries = tmp;

	LPHOOK_ENTRY entry = &lpDllInfo->HookEntries[lpDllInfo->HookEntryCount];
	strncpy_s(entry->FunctionName, sizeof(entry->FunctionName), functionName, _TRUNCATE);
	wcsncpy_s(entry->HookingLibrary, MAX_PATH, hookingLibrary, _TRUNCATE);

	lpDllInfo->HookEntryCount++;
	return TRUE;
}

DWORD GetRowTotalHooks(LPSUMMARY_TABLE_ROW lpRow)
{
	DWORD total = 0;
	for (DWORD i = 0; i < lpRow->DllsCount; i++)
		total += lpRow->DllInfos[i].HookEntryCount;
	return total;
}

/*
* Collects unique hooking library names from the given rows.
* Returns a malloc'd array of _wcsdup'd strings; caller must free each entry and the array.
*/
static WCHAR** CollectUniqueLibraries(LPSUMMARY_TABLE_ROW rows, DWORD rowCount, DWORD* outCount)
{
	WCHAR** libs = NULL;
	DWORD count = 0;
	DWORD capacity = 0;

	for (DWORD i = 0; i < rowCount; i++)
	{
		LPSUMMARY_TABLE_ROW row = &rows[i];
		for (DWORD j = 0; j < row->DllsCount; j++)
		{
			LPDLL_INFO di = &row->DllInfos[j];
			for (DWORD k = 0; k < di->HookEntryCount; k++)
			{
				BOOL found = FALSE;
				for (DWORD u = 0; u < count; u++)
				{
					if (_wcsicmp(libs[u], di->HookEntries[k].HookingLibrary) == 0)
					{ found = TRUE; break; }
				}
				if (!found)
				{
					if (count >= capacity)
					{
						capacity = capacity == 0 ? 8 : capacity * 2;
						WCHAR** t = (WCHAR**)realloc(libs, capacity * sizeof(WCHAR*));
						if (!t) break;
						libs = t;
					}
					libs[count++] = _wcsdup(di->HookEntries[k].HookingLibrary);
				}
			}
		}
	}

	*outCount = count;
	return libs;
}

static void FreeUniqueLibraries(WCHAR** libs, DWORD count)
{
	for (DWORD i = 0; i < count; i++)
		free(libs[i]);
	free(libs);
}

void PrintFullTable(LPSUMMARY_TABLE lpSummaryTable)
{
	wprintf(L"\n\n*** SUMMARY ***\n\n");

	if (lpSummaryTable->RowsCount == 0) {
		wprintf(L"No hooks found!\n");
		return;
	}

	for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
	{
		LPSUMMARY_TABLE_ROW row = &lpSummaryTable->Rows[i];
		DWORD totalHooks = GetRowTotalHooks(row);
		wprintf(L"[+] PID: %lu - %lu hooks found\n", row->Pid, totalHooks);

		for (DWORD j = 0; j < row->DllsCount; j++)
		{
			LPDLL_INFO di = &row->DllInfos[j];
			wprintf(L"    %ls: %lu hooks\n", di->DllFullPath, di->HookEntryCount);
		}

		/* Collect unique hooking libraries for this PID */
		DWORD uniqueLibCount = 0;
		WCHAR** uniqueLibs = CollectUniqueLibraries(row, 1, &uniqueLibCount);

		if (uniqueLibCount > 0)
			wprintf(L"  Hooking libraries:\n");

		for (DWORD u = 0; u < uniqueLibCount; u++)
		{
			wprintf(L"    %ls hooks:\n", GetFileNameFromPath(uniqueLibs[u]));
			for (DWORD j = 0; j < row->DllsCount; j++)
			{
				LPDLL_INFO di = &row->DllInfos[j];
				const wchar_t* modName = GetFileNameFromPath(di->DllFullPath);
				for (DWORD k = 0; k < di->HookEntryCount; k++)
				{
					if (_wcsicmp(di->HookEntries[k].HookingLibrary, uniqueLibs[u]) == 0)
						wprintf(L"      - %ls!%hs\n", modName, di->HookEntries[k].FunctionName);
				}
			}
		}
		FreeUniqueLibraries(uniqueLibs, uniqueLibCount);

		wprintf(L"\n");
	}
}

void PrintAggregateReport(LPSUMMARY_TABLE lpSummaryTable)
{
	wprintf(L"\n\n*** AGGREGATE REPORT ***\n\n");

	if (lpSummaryTable->RowsCount == 0) {
		wprintf(L"No hooks found!\n");
		return;
	}

	/* Collect all unique hooking libraries across all PIDs */
	DWORD uniqueLibCount = 0;
	WCHAR** uniqueLibs = CollectUniqueLibraries(lpSummaryTable->Rows, lpSummaryTable->RowsCount, &uniqueLibCount);

	for (DWORD u = 0; u < uniqueLibCount; u++)
	{
		wprintf(L"Hooking library: %ls\n", uniqueLibs[u]);

		/* Print PIDs that contain this hooking library */
		wprintf(L"  Injected into PIDs: ");
		BOOL firstPid = TRUE;
		for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
		{
			LPSUMMARY_TABLE_ROW row = &lpSummaryTable->Rows[i];
			BOOL pidHasLib = FALSE;
			for (DWORD j = 0; j < row->DllsCount && !pidHasLib; j++)
			{
				LPDLL_INFO di = &row->DllInfos[j];
				for (DWORD k = 0; k < di->HookEntryCount; k++)
				{
					if (_wcsicmp(di->HookEntries[k].HookingLibrary, uniqueLibs[u]) == 0)
					{ pidHasLib = TRUE; break; }
				}
			}
			if (pidHasLib)
			{
				if (!firstPid) wprintf(L", ");
				wprintf(L"%lu", row->Pid);
				firstPid = FALSE;
			}
		}
		wprintf(L"\n");

		/* Print unique hooked functions for this library */
		wprintf(L"  Hooked functions:\n");
		CHAR** printedFuncs = NULL;
		DWORD printedCount = 0;

		for (DWORD i = 0; i < lpSummaryTable->RowsCount; i++)
		{
			LPSUMMARY_TABLE_ROW row = &lpSummaryTable->Rows[i];
			for (DWORD j = 0; j < row->DllsCount; j++)
			{
				LPDLL_INFO di = &row->DllInfos[j];
				const wchar_t* modName = GetFileNameFromPath(di->DllFullPath);
				for (DWORD k = 0; k < di->HookEntryCount; k++)
				{
					LPHOOK_ENTRY he = &di->HookEntries[k];
					if (_wcsicmp(he->HookingLibrary, uniqueLibs[u]) != 0)
						continue;

					char key[512];
					sprintf_s(key, sizeof(key), "%ls!%s", modName, he->FunctionName);

					BOOL already = FALSE;
					for (DWORD p = 0; p < printedCount; p++)
					{
						if (strcmp(printedFuncs[p], key) == 0)
						{ already = TRUE; break; }
					}
					if (!already)
					{
						wprintf(L"    - %ls!%hs\n", modName, he->FunctionName);
						CHAR** t = (CHAR**)realloc(printedFuncs, (printedCount + 1) * sizeof(CHAR*));
						if (t) { printedFuncs = t; printedFuncs[printedCount++] = _strdup(key); }
					}
				}
			}
		}

		for (DWORD p = 0; p < printedCount; p++)
			free(printedFuncs[p]);
		free(printedFuncs);

		wprintf(L"\n");
	}
	FreeUniqueLibraries(uniqueLibs, uniqueLibCount);
}
