#include <Windows.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>

int note_PID;




char* GetDllPath() { //searching
	char path[MAX_PATH];
	HMODULE hModule = GetModuleHandle(NULL);
	if (hModule != NULL) {
		GetModuleFileNameA(hModule, path, sizeof(path));
	}

	// .exe를 .dll로 변경
	char* pos = strrchr(path, '.');
	if (pos != NULL && strcmp(pos, ".exe") == 0) {
		strcpy(pos, ".dll");
	}

	// 결과를 동적 메모리에 복사
	char* dllPath = (char*)malloc(strlen(path) + 1);
	if (dllPath != NULL) {
		strcpy(dllPath, path);
	}

	return dllPath;
}
int PrintProcessNameAndID(DWORD processID, const TCHAR* name) // 
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
		}
	}

	if (_tcscmp(szProcessName, name) == 0)
	{
		CloseHandle(hProcess);
		return 1;
	}


	CloseHandle(hProcess);
	return 0;
}

int find(const TCHAR* name)
{

	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return 1;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			if (PrintProcessNameAndID(aProcesses[i], name))
			{
				// found it
				_tprintf(TEXT("%d %s\n"), aProcesses[i], name);
				note_PID = aProcesses[i];
			}
		}
	}
	return 0;
}

void InjectDLL(DWORD pid, LPCSTR dll) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (NULL == hProcess)
	{
		printf("Process not found\n");
		return;
	}
	LPVOID lpAddr = VirtualAllocEx(hProcess, NULL, strlen(dll) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (lpAddr)
	{
		WriteProcessMemory(hProcess, lpAddr, dll, strlen(dll) + 1, NULL);
	}
	else
	{
		printf("VirtualAllocEx() failure.\n");
		return;
	}
	LPTHREAD_START_ROUTINE pfnLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (pfnLoadLibraryA)
	{
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnLoadLibraryA, lpAddr, 0, NULL);
		DWORD dwExitCode = NULL;
		if (hThread)
		{
			printf("Injection successful!\n");
			WaitForSingleObject(hThread, INFINITE);
			if (GetExitCodeThread(hThread, &dwExitCode))
				printf("Injected DLL ImageBase: %#x\n", dwExitCode);
			CloseHandle(hThread);
		}
		else
		{
			printf("Injection failure.\n");
		}
	}
	VirtualFreeEx(hProcess, lpAddr, 0, MEM_RELEASE); //VirtualAllocEx로 획득한 힙 반환
	CloseHandle(hProcess);
}
int main() {
	HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("Global\\keto1234"));
	if (hEvent == NULL) {
		std::cerr << "Failed to create event: " << GetLastError() << std::endl;
		return 1;
	}
	HANDLE hEvent2 = CreateEvent(NULL, TRUE, FALSE, TEXT("Global\\stopspyyy"));
	if (hEvent2 == NULL) {
		std::cerr << "Failed to create event: " << GetLastError() << std::endl;
		return 1;
	}
	char a = 0;
	char ex[10] = { 0 };
	find(TEXT("notepad++.exe"));
	DWORD pid = NULL;
	char* path = GetDllPath();

	if (GetFileAttributesA(path) == 0xffffffff) {
		printf("DLL not found.\n");
		free(path);
		return 1;
	}
	printf("Target Process PID: ");
	pid = note_PID;


	InjectDLL(pid, path);
	printf("time and APM will be displayed in sector number 1\n");
	printf("Say 'y' When you want to spy on the notepad++: (If u do not want, press say 'n')");
	scanf("%c", &a);
	if (a == 'y' || a == 'Y') {
		if (!SetEvent(hEvent)) {
			std::cerr << "Failed to signal event: " << GetLastError() << std::endl;
			CloseHandle(hEvent);
			free(path);
			return 1;
		}
		printf("attack sucess\n");
		Sleep(1000);
		CloseHandle(hEvent);
		free(path);
		return 0;
	}



}