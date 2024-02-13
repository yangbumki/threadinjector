#include <Windows.h>
#include <iostream>

#include "ThreadInjection.hpp"

static DWORD WINAPI ThreadProc(_In_ LPVOID args) {
	return 0;
};

int main(void) {
	setlocale(LC_ALL, "");
	ti threadInjector;

	threadInjector.SetThreadInjection(L"notepad.exe", ThreadProc);

	return 0;
};