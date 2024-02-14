#pragma once

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#define BUFSIZE		1024
#define	RET			0x3C

typedef struct CreateThreadArgument {
	_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes;
	_In_ SIZE_T dwStackSize;
	_In_ LPTHREAD_START_ROUTINE lpStartAddress;
	_In_opt_ __drv_aliasesMem LPVOID lpParameter;
	_In_ DWORD dwCreationFlags;
	_Out_opt_ LPDWORD lpThreadId;
}ctarg;

typedef class THREAD_INEJECTOR {
private:
	WCHAR exeName[BUFSIZE] = { 0, };
	HANDLE snapShot = NULL;
	PROCESSENTRY32 pe32;

	HANDLE process = NULL, remoteThread = NULL;
	LPTHREAD_START_ROUTINE threadFunc = NULL;
	DWORD threadSize = 0;
	LPVOID remoteAllocAddr = NULL;

	void WarningMessage(const char* msg) {
		printf("%s \n", msg);
	};

	void ErrorMessage(const char* msg) {
		MessageBoxA(NULL, msg, "ERROR", NULL);
		exit(-1);
	};

	BOOL GetProcess(const WCHAR* name) {
		SetExeName(name);

		if (snapShot != NULL) WarningMessage("SnapShot is not invalid");
		snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		if (snapShot == NULL) ErrorMessage("CreateToolhelp32Snapshot()");

		memset(&pe32, 0, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(snapShot, &pe32)) ErrorMessage("Process32First()");

		int result = 0, result2;

		while (Process32Next(snapShot, &pe32)) {

			if (snapShot == NULL) {
				WarningMessage("Process is not found");
				return FALSE;
			};
			wprintf_s(L"%s\n", pe32.szExeFile);
			result = _wcsicmp(pe32.szExeFile, GetExeName());
			if (result == 0) return TRUE;
		};

		return FALSE;
	};

	BOOL SetRemoteThreadFunction(LPTHREAD_START_ROUTINE func) {
		if (func == NULL) {
			WarningMessage("Function NULL");
			return false;
		}

		this->threadFunc = func;
	};

	BOOL GetFunctionSize() {
		if (this->threadFunc == NULL) {
			WarningMessage("ThreadFunc is not valid");
			return false;
		};

		void* temp = this->threadFunc;
		int size = 0;
		do {
			temp = (char*)temp + 1;
			size++;
		} while ((char)temp != RET);

		this->threadSize = size + sizeof(DWORD);
		return TRUE;
	};

public:
	THREAD_INEJECTOR() {

	};

	~THREAD_INEJECTOR() {
	};

	void SetThreadFuncSize(void* f1, void* f2) {
		auto result = (DWORD)f2 - (DWORD)f1;
		this->threadSize = result;
	};

	void SetExeName(const WCHAR* name) {
		memset(this->exeName, 0, BUFSIZE);
		wcscpy_s(this->exeName, name);
	};

	WCHAR* GetExeName() {
		return this->exeName;
	};

	BOOL SetThreadInjection1(const WCHAR* eName, LPTHREAD_START_ROUTINE func) {
		if (!SetRemoteThreadFunction(func)) ErrorMessage("SetRemoteThreadFunction()");
		if (!GetProcess(eName)) ErrorMessage("GetProcess()");

		if (process != NULL) WarningMessage("Process is not invalid");
		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (process == NULL) ErrorMessage("OpenProcess()");

		if (remoteAllocAddr != NULL) WarningMessage("remoteAllocAddr is not invalid");
		if (!GetFunctionSize()) ErrorMessage("GetFunctionSize()");
		remoteAllocAddr = VirtualAllocEx(process, NULL, threadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (remoteAllocAddr == NULL) ErrorMessage("VirtualAllocEx()");

		if (!WriteProcessMemory(this->process, remoteAllocAddr, threadFunc, threadSize, NULL)) ErrorMessage("WriteProcessMemory()");

		if (remoteThread != NULL) ErrorMessage("RemoteThread is not invalid");
		remoteThread = CreateRemoteThreadEx(this->process, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAllocAddr, NULL, 0, 0, NULL);
		if (remoteThread == NULL) ErrorMessage("CreateRemoteThread()");

		WaitForSingleObject(remoteThread, INFINITY);

		return TRUE;
	};

	BOOL SetThreadInjection2(const WCHAR* eName, LPTHREAD_START_ROUTINE func) {
		if (!SetRemoteThreadFunction(func)) ErrorMessage("SetRemoteThreadFunction()");
		if (!GetProcess(eName)) ErrorMessage("GetProcess()");

		if (process != NULL) WarningMessage("Process is not invalid");
		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (process == NULL) ErrorMessage("OpenProcess()");

		if (remoteAllocAddr != NULL) WarningMessage("remoteAllocAddr is not invalid");
		if (!GetFunctionSize()) ErrorMessage("GetFunctionSize()");
		remoteAllocAddr = VirtualAllocEx(process, NULL, threadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (remoteAllocAddr == NULL) ErrorMessage("VirtualAllocEx()");
		if (!WriteProcessMemory(this->process, remoteAllocAddr, threadFunc, threadSize, NULL)) ErrorMessage("WriteProcessMemory()");

		//CreateThread 내부 인자값에 모두 전달이아니라 특정 레지스터에만 전달됨
		/*LPVOID remoteAllocAddr2 = NULL;
		CreateThreadArgument cta = { 0, };
		cta.lpStartAddress = (LPTHREAD_START_ROUTINE)remoteAllocAddr;
		remoteAllocAddr2 = VirtualAllocEx(process, NULL, sizeof(cta), MEM_COMMIT, PAGE_READWRITE);
		if (remoteAllocAddr2 == NULL) ErrorMessage("VirtualAllocEx() - 2");
		if (!WriteProcessMemory(process, remoteAllocAddr2, (LPCVOID)&cta, sizeof(cta), NULL)) ErrorMessage("WriteProcessMemory() - 2");*/

		//CreateThread 불러오는 함수
		HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
		if (kernel32 == NULL) ErrorMessage("GetModuleHandleA()");
		FARPROC SetCreateThread = GetProcAddress(kernel32, "CreateThread");
		if (SetCreateThread == NULL) ErrorMessage("GetProcAddress()");

		if (remoteThread != NULL) ErrorMessage("RemoteThread is not invalid");
		remoteThread = CreateRemoteThreadEx(this->process, NULL, 0, (LPTHREAD_START_ROUTINE)SetCreateThread, remoteAllocAddr, 0, 0, NULL);
		if (remoteThread == NULL) ErrorMessage("CreateRemoteThread()");

		//RemoteThreadEx로 직접 불러오는 함수
		/*if (remoteThread != NULL) ErrorMessage("RemoteThread is not invalid");
		remoteThread = CreateRemoteThreadEx(this->process, NULL, 0, (LPTHREAD_START_ROUTINE)this->remoteAllocAddr, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, 0, NULL);
		if (remoteThread == NULL) ErrorMessage("CreateRemoteThread()");*/

		WaitForSingleObject(remoteThread, INFINITY);

		return TRUE;
	};

	BOOL SetThreadInjection3(const WCHAR* eName, void* func) {
		if (!SetRemoteThreadFunction((LPTHREAD_START_ROUTINE)func)) ErrorMessage("SetRemoteThreadFunction()");
		if (!GetProcess(eName)) ErrorMessage("GetProcess()");

		if (process != NULL) WarningMessage("Process is not invalid");
		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (process == NULL) ErrorMessage("OpenProcess()");

		if (remoteAllocAddr != NULL) WarningMessage("remoteAllocAddr is not invalid");
		if (!GetFunctionSize()) ErrorMessage("GetFunctionSize()");
		remoteAllocAddr = VirtualAllocEx(process, NULL, threadSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (remoteAllocAddr == NULL) ErrorMessage("VirtualAllocEx()");
		if (!WriteProcessMemory(this->process, remoteAllocAddr, threadFunc, threadSize, NULL)) ErrorMessage("WriteProcessMemory()");

		//CreateThread 내부 인자값에 모두 전달이아니라 특정 레지스터에만 전달됨
		/*LPVOID remoteAllocAddr2 = NULL;
		CreateThreadArgument cta = { 0, };
		cta.lpStartAddress = (LPTHREAD_START_ROUTINE)remoteAllocAddr;
		remoteAllocAddr2 = VirtualAllocEx(process, NULL, sizeof(cta), MEM_COMMIT, PAGE_READWRITE);
		if (remoteAllocAddr2 == NULL) ErrorMessage("VirtualAllocEx() - 2");
		if (!WriteProcessMemory(process, remoteAllocAddr2, (LPCVOID)&cta, sizeof(cta), NULL)) ErrorMessage("WriteProcessMemory() - 2");*/

		//CreateThread 불러오는 함수
		HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
		if (kernel32 == NULL) ErrorMessage("GetModuleHandleA()");
		FARPROC SetCreateThread = GetProcAddress(kernel32, "CreateThread");
		if (SetCreateThread == NULL) ErrorMessage("GetProcAddress()");

		if (remoteThread != NULL) ErrorMessage("RemoteThread is not invalid");
		remoteThread = CreateRemoteThreadEx(this->process, NULL, 0, (LPTHREAD_START_ROUTINE)SetCreateThread, remoteAllocAddr, 0, 0, NULL);
		if (remoteThread == NULL) ErrorMessage("CreateRemoteThread()");

		//RemoteThreadEx로 직접 불러오는 함수
		/*if (remoteThread != NULL) ErrorMessage("RemoteThread is not invalid");
		remoteThread = CreateRemoteThreadEx(this->process, NULL, 0, (LPTHREAD_START_ROUTINE)this->remoteAllocAddr, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, 0, NULL);
		if (remoteThread == NULL) ErrorMessage("CreateRemoteThread()");*/

		WaitForSingleObject(remoteThread, INFINITY);

		return TRUE;
	};



}ThreadInjector, ti;