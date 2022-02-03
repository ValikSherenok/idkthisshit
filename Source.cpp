#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

const char* pattern = "\x55\x8B\xEC\x56\x8B\xF1\x33\xC0\x57\x8B\x7D\x08\x8B\x8E\x00\x00\x00\x00\x85\xC9\x7E\x12\x3B\x3C\x86\x72\x06\x3B\x7C\x86\x04\x72\x49\x83\xC0\x02\x3B\xC1\x7C\xEE";
const char* patternMask = "xxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxx";
const unsigned char patch[5] = { 0xB0, 0x01, 0xC2, 0x04, 0x00 };
const wchar_t* module_to_patch[4] = {
	L"engine.dll",
	L"materialsystem.dll",
	L"studiorender.dll",
	L"client.dll"
};

int cofpatch = 0;

DWORD GetProcessID(const wchar_t* processName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;
	PROCESSENTRY32W ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32FirstW(hSnap, &ProcEntry))
	{
		do {
			if(!wcscmp(ProcEntry.szExeFile, processName))
			{
				CloseHandle(hSnap);
				return ProcEntry.th32ProcessID;
			}
		}while(Process32NextW(hSnap, &ProcEntry));
	}
	else
	{
		CloseHandle(hSnap);
		return 0;
	}

	CloseHandle(hSnap);
	return 0;
}

std::pair<DWORD, DWORD> GetModule(const wchar_t* moduleName, DWORD processID) {
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
	MODULEENTRY32W mEntry;
	mEntry.dwSize = sizeof(MODULEENTRY32W);
	if (!Module32FirstW(hmodule, &mEntry))
		return std::make_pair(0, 0);
	do {
		if (!wcscmp(mEntry.szModule, moduleName)) {
			CloseHandle(hmodule);
			return std::make_pair((DWORD)mEntry.hModule, mEntry.modBaseSize);
		}
	} while (Module32NextW(hmodule, &mEntry));

	return std::make_pair(0, 0);
}

template <typename var>
var ReadMemory(HANDLE hProcess, DWORD Address) {
	var value;
	ReadProcessMemory(hProcess, (LPCVOID)Address, &value, sizeof(var), NULL);
	return value;
}

bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

DWORD FindSignature(HANDLE ProcID, DWORD start, DWORD size, const char* sig, const char* mask)
{
	BYTE* data = new BYTE[size];
	SIZE_T bytesRead;

	ReadProcessMemory(ProcID, (LPVOID)start, data, size, &bytesRead);

	for (DWORD i = 0; i < size; i++)
	{
		if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
			return start + i;
		}
	}
	delete[] data;
	return NULL;
}

void PatchModule(HANDLE hProc, DWORD pID, const wchar_t* modname)
{
	std::pair<DWORD, DWORD> module = GetModule(modname, pID);
	if (!module.first && !module.second) {
		std::cout << "Did not found module" << std::endl;
		return;
	}
	DWORD sig = FindSignature(hProc, module.first, module.second, pattern, patternMask);
	while (sig)
	{
		WriteProcessMemory(hProc, (LPVOID)sig, patch, 5, 0);
		std::wcout << modname << std::endl;
		cofpatch++;
		sig = FindSignature(hProc, module.first, module.second, pattern, patternMask);
	}
	return;
}

int main(int argc, char* argv[])
{
	
	DWORD procID = GetProcessID(L"csgo.exe");
	if (!procID) {
		std::cout << "Did not found process" << std::endl;
		return 1;
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
	for (int i = 0; i < 4; i++)
	{
		PatchModule(hProc, procID, module_to_patch[i]);
	}
	/*
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procID);
	MODULEENTRY32W mEntry;
	mEntry.dwSize = sizeof(MODULEENTRY32W);
	if (!Module32FirstW(hmodule, &mEntry))
		return 0;

	do {
		
	} while (Module32NextW(hmodule, &mEntry));
	*/
	std::cout << "Count of patch: " << cofpatch << std::endl;
	std::cin >> procID;
	return 0;
}