#include "pch.h"

#include "deobfuscator.hpp"
#pragma comment(lib, "xed.lib")

#include <TlHelp32.h>
#include <tchar.h>

void find_module(LPCTSTR processName, void(*fn)(DWORD))
{
	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	// Set the size of the structure before using it.
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	for (BOOL succeeded = Process32First(hProcessSnap, &pe32);
		succeeded; Process32Next(hProcessSnap, &pe32))
	{
		static size_t c_nLength = _tcslen(processName);
		size_t nLength = _tcslen(pe32.szExeFile);
		if (nLength < c_nLength ||
			_tcscmp(pe32.szExeFile + nLength - c_nLength, processName) != 0)
		{
			continue;
		}

		fn(pe32.th32ProcessID);
		break;
	}

	CloseHandle(hProcessSnap);
}

int main()
{
	// Once, before using Intel XED, you must call xed_tables_init() to initialize the tables Intel XED uses for encoding and decoding:
	xed_tables_init();

	try
	{
		find_module(L"devirtualizeme32_vmp_3.0.9_v1.exe", vmprotect_test);
	}
	catch (const std::exception &ex)
	{
		std::cout << ex.what() << std::endl;
	}
	return 0;
}