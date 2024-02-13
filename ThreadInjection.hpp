#pragma once

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#define BUFSIZE		1024
#define	RET			0x3C

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

	void SetExeName(const WCHAR* name) {
		memset(this->exeName, 0, BUFSIZE);
		wcscpy_s(this->exeName, name);
	};

	WCHAR* GetExeName() {
		return this->exeName;
	};

	BOOL SetThreadInjection(const WCHAR* eName, LPTHREAD_START_ROUTINE func) {
		if (!SetRemoteThreadFunction(func)) ErrorMessage("SetRemoteThreadFunction()");
		if (!GetProcess(eName)) ErrorMessage("GetProcess()");

		if (process != NULL) WarningMessage("Process is not invalid");
		process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (process == NULL) ErrorMessage("OpenProcess()");

		if (remoteAllocAddr != NULL) WarningMessage("remoteAllocAddr is not invalid");
		if (!GetFunctionSize()) ErrorMessage("GetFunctionSize()");
		remoteAllocAddr = VirtualAllocEx(process, NULL, threadSize, MEM_COMMIT, PAGE_READWRITE);
		if (remoteAllocAddr == NULL) ErrorMessage("VirtualAllocEx()");

		if (!WriteProcessMemory(this->process, remoteAllocAddr, threadFunc, threadSize, NULL)) ErrorMessage("WriteProcessMemory()");

		if (remoteThread != NULL) ErrorMessage("RemoteThread is not invalid");
		remoteThread = CreateRemoteThreadEx(this->process, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAllocAddr, NULL, 0, 0,NULL);
		if (remoteThread == NULL) ErrorMessage("CreateRemoteThread()");

		WaitForSingleObject(remoteThread, INFINITY);

		return TRUE;
	};



}ThreadInjector, ti;