#include <Windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <psapi.h>
#include "SummaryTable.h"
#include "HookSentry.h"

#pragma comment(lib, "psapi")

/*
* Finds all PIDs whose base module name matches the given process name (case-insensitive).
* Returns the number of PIDs written into outPids (up to maxOut).
*/
static DWORD ResolveProcessName(const wchar_t* name, DWORD* outPids, DWORD maxOut)
{
	DWORD allPids[1024], cbNeeded;
	if (!EnumProcesses(allPids, sizeof(allPids), &cbNeeded))
		return 0;

	DWORD count = cbNeeded / sizeof(DWORD);
	DWORD found = 0;

	for (DWORD i = 0; i < count && found < maxOut; i++)
	{
		if (allPids[i] == 0)
			continue;

		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, allPids[i]);
		if (!hProc)
			continue;

		wchar_t baseName[MAX_PATH];
		if (GetModuleBaseNameW(hProc, NULL, baseName, MAX_PATH) > 0)
		{
			if (_wcsicmp(baseName, name) == 0)
				outPids[found++] = allPids[i];
		}
		CloseHandle(hProc);
	}
	return found;
}

/*
* Parses a comma-separated list of PIDs and/or process names.
* Numeric tokens are treated as PIDs; non-numeric tokens are resolved to PIDs by name.
* Returns a malloc'd array of DWORDs; caller must free(). Sets *outCount.
* Returns NULL on failure.
*/
static DWORD* ParseTargets(const wchar_t* arg, SIZE_T* outCount)
{
	*outCount = 0;

	SIZE_T capacity = 16;
	DWORD* pids = (DWORD*)malloc(capacity * sizeof(DWORD));
	if (!pids)
		return NULL;

	/* Make a mutable copy for wcstok */
	SIZE_T len = wcslen(arg) + 1;
	wchar_t* buf = (wchar_t*)malloc(len * sizeof(wchar_t));
	if (!buf) { free(pids); return NULL; }
	wcscpy_s(buf, len, arg);

	wchar_t* ctx = NULL;
	wchar_t* token = wcstok_s(buf, L",", &ctx);
	while (token != NULL)
	{
		/* Try to parse as a number */
		wchar_t* endPtr = NULL;
		long val = wcstol(token, &endPtr, 10);
		if (endPtr != token && *endPtr == L'\0' && val > 0)
		{
			/* It's a PID */
			if (*outCount >= capacity)
			{
				capacity *= 2;
				DWORD* tmp = (DWORD*)realloc(pids, capacity * sizeof(DWORD));
				if (!tmp) { free(pids); free(buf); return NULL; }
				pids = tmp;
			}
			pids[(*outCount)++] = (DWORD)val;
		}
		else
		{
			/* Treat as process name */
			DWORD resolved[256];
			DWORD nResolved = ResolveProcessName(token, resolved, 256);
			if (nResolved == 0)
			{
				wprintf(L"[!] No process found with name: %ls\n", token);
			}
			for (DWORD r = 0; r < nResolved; r++)
			{
				if (*outCount >= capacity)
				{
					capacity *= 2;
					DWORD* tmp = (DWORD*)realloc(pids, capacity * sizeof(DWORD));
					if (!tmp) { free(pids); free(buf); return NULL; }
					pids = tmp;
				}
				pids[(*outCount)++] = resolved[r];
			}
		}
		token = wcstok_s(NULL, L",", &ctx);
	}

	free(buf);
	if (*outCount == 0) { free(pids); return NULL; }
	return pids;
}

static void SearchHooksInPIDs(DWORD* pids, SIZE_T pidListSize, BOOL verbose, BOOL printDisass, BOOL aggregate)
{
	SUMMARY_TABLE table;
	InitSummaryTable(&table);

	for (DWORD count = 0; count < pidListSize; count++)
	{
		print_verbose(verbose, L"---\n[*] Working on process %d of %zu with PID: %lu\n", count + 1, pidListSize, pids[count]);

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[count]);
		if (!hProcess) {
			print_verbose(verbose, L"[-] Cannot open an handle on PID: %lu  (Low priv?)\n", pids[count]);
			continue;
		}

		if (!SearchHooks(hProcess, &table, verbose, printDisass))
			print_verbose(verbose, L"[!] Task failed for process %lu. Skipping.\n", pids[count]);

		CloseHandle(hProcess);
	}

	PrintFullTable(&table);
	if (aggregate)
		PrintAggregateReport(&table);
	FreeSummaryTable(&table);
}

static void PrintUsage()
{
	wprintf(L"Usage: HookSentry.exe [-a|-p <targets>|-v|-d|-o <file>]\n");
	wprintf(L"Options:\n");
	wprintf(L"\t-h, --help: Show this message\n");
	wprintf(L"\t-p, --pid <targets>: Comma-separated list of PIDs or process names\n");
	wprintf(L"\t                     (e.g. -p 1234,notepad.exe,5678)\n");
	wprintf(L"\t-a, --all: Analyze all active processes\n");
	wprintf(L"\t-v, --verbose: Enable verbose output\n");
	wprintf(L"\t-d, --disass: Display disassembled code\n");
	wprintf(L"\t-o, --output <file>: Write all output to file\n");
}

int wmain(int argc, wchar_t* argv[])
{
	wchar_t banner[] = L""
		"\n|_| _  _ | (~ _  _ _|_ _\n"
		"| |(_)(_)|<_)(/_| | | |\\/\n"
		"                      /\nV0.5.1\n\n";
	wprintf(L"%s", banner);

	DWORD* targetPids = NULL;
	SIZE_T targetCount = 0;
	BOOL verbose = FALSE;
	BOOL disass = FALSE;
	BOOL fullScan = FALSE;
	PWSTR outputFile = NULL;

	for (int i = 1; i < argc; i++)
	{
		// -h, --help --> Print Usage
		if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0)
		{
			PrintUsage();
			return 1;
		}

		// -p <targets>, --pid <targets> --> Work on specific PIDs/process names
		else if (wcscmp(argv[i], L"-p") == 0 || wcscmp(argv[i], L"--pid") == 0)
		{
			if (i + 1 >= argc) {
				wprintf(L"Missing argument for -p.\n\n");
				PrintUsage();
				return 1;
			}
			targetPids = ParseTargets(argv[i + 1], &targetCount);
			if (targetPids == NULL || targetCount == 0) {
				wprintf(L"No valid targets found in: %ls\n\n", argv[i + 1]);
				PrintUsage();
				return 1;
			}
			i++;
		}

		// -v, --verbose --> Verbose output
		else if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--verbose") == 0)
		{
			verbose = TRUE;
		}

		// -a, --all --> Works on all active processes
		else if (wcscmp(argv[i], L"-a") == 0 || wcscmp(argv[i], L"--all") == 0)
		{
			fullScan = TRUE;
		}

		// -d, --disass --> Print disassembled code
		else if (wcscmp(argv[i], L"-d") == 0 || wcscmp(argv[i], L"--disass") == 0)
		{
#ifdef _CS_ENABLED
			disass = TRUE;
#else
			wprintf(L"[!] Disassembly not available in this build.\n");
#endif
		}

		// -o <file>, --output <file> --> Write output to file
		else if (wcscmp(argv[i], L"-o") == 0 || wcscmp(argv[i], L"--output") == 0)
		{
			if (i + 1 >= argc) {
				wprintf(L"Missing argument for -o.\n\n");
				PrintUsage();
				return 1;
			}
			outputFile = argv[i + 1];
			i++;
		}

		else
		{
			wprintf(L"[!] Unknown argument: %ls\n\n", argv[i]);
			PrintUsage();
			return 1;
		}
	}

	/* Redirect stdout to file if -o was specified */
	FILE* outFileStream = NULL;
	if (outputFile != NULL)
	{
		if (_wfreopen_s(&outFileStream, outputFile, L"w", stdout) != 0)
		{
			fwprintf(stderr, L"[!] Failed to open output file: %ls\n", outputFile);
			return 1;
		}
		fwprintf(stderr, L"[*] Output redirected to: %ls\n", outputFile);
	}

	if (!fullScan && targetPids == NULL)
	{
		print_verbose(verbose, L"[*] Selected current process.\n");

		DWORD pids[] = { GetCurrentProcessId() };
		SearchHooksInPIDs(pids, 1, verbose, disass, FALSE);
	}

	else if (!fullScan && targetPids != NULL)
	{
		SearchHooksInPIDs(targetPids, targetCount, verbose, disass, targetCount > 1);
		free(targetPids);
	}

	else if (fullScan)
	{
		print_verbose(verbose, L"[*] Full system scan requested (could take a while)\n");

		DWORD pids[1024], cbNeeded, cbPids;
		if (!EnumProcesses(pids, sizeof(pids), &cbNeeded))
		{
			wprintf(L"[-] Failed to enumerate processes.\n");
			if (outFileStream) fclose(outFileStream);
			return 1;
		}
		cbPids = cbNeeded / sizeof(DWORD);
		print_verbose(verbose, L"[*] %lu active processes found\n", cbPids);

		SearchHooksInPIDs(pids, cbPids, verbose, disass, TRUE);
	}

	if (outFileStream)
		fclose(outFileStream);

	return 0;
}
