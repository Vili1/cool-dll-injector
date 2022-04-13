#include <fstream>
#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <direct.h> // _getcwd
#include <string>
#include <iomanip>
#include <sstream>
#include <process.h>
#include <ctime>
#include <unordered_set>
#include "makesyscall.h"
#pragma comment(lib,"ntdll.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

using namespace std;

DWORD FindProcessId(const std::wstring&);
long InjectProcess(DWORD, const char*);


int main_scanner();

string GetExeFileName();
string GetExePath();

__declspec(naked) void stub()
{
	__asm
	{
		// Save registers

		pushad
		pushfd
		call start // Get the delta offset

		start :
		pop ecx
			sub ecx, 7

			lea eax, [ecx + 32] // 32 = Code length + 11 int3 + 1
			push eax
			call dword ptr[ecx - 4] // LoadLibraryA address is stored before the shellcode

			// Restore registers

			popfd
			popad
			ret

			// 11 int3 instructions here
	}
}

// this way we can difference the addresses of the instructions in memory
DWORD WINAPI stub_end()
{
	return 0;
}
//
auto titleGen = [](int num)
{
	std::string titleName;
	for (int i = 0; i < num; i++)
	{
		titleName += rand() % 69 + 69;
	}
	return titleName;
};

void polymorphic()
{
	std::srand(std::time(0));
	for (int count = 0; count < 10; count++)
	{
		int index = rand() % (6 - 0 + 1) + 0;
		switch (index)
		{
		case 0:
			__asm __volatile
				{
					sub eax, 3
					add eax, 1
					add eax, 2
				}
		case 1:
			__asm __volatile
				{
					push eax
					pop eax
				}
		case 2:
			__asm __volatile
				{
					inc eax
					dec eax
				}
		case 3:
			__asm __volatile
				{
					dec eax
					add eax, 1
				}
		case 4:
			__asm __volatile
				{
					pop eax
					push eax
				}
		case 5:
			__asm __volatile
				{
					mov eax, eax
					sub eax, 1
					add eax, 1
				}
		case 6:
			__asm __volatile
				{
					xor eax, eax
					mov eax, eax
				}
		}
	}
}
int main(int argc, char* argv) {
	main_scanner();
	return 0;
}


string GetExeFileName()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	return std::string(buffer);
}

string GetExePath()
{
	std::string f = GetExeFileName();
	return f.substr(0, f.find_last_of("\\/"));
}

int main_scanner() {
	std::cout << "Loading";

	std::cout << endl;

	std::system("cls");

	string L = "L";
	string I = "I";
	string e = "e";
	string E = "E";
	string t = "t";
	string B = "B";
	string a = "a";
	string A = "A";
	string C = "C";
	string r = "r";
	string g = "g";
	string n = "n";
	string u = "u";
	string l = "l";
	string space = " ";
	string h = "h";
	string w = "w";
	string d = "d";
	string G = "G";
	string m = "m";
	string o = "o";
	string f = "f";
	string s = "s";
	string dot = ".";
	string x = "x";
	string c = "c";

	string processName = L + e + a + g + u + e + space + o + f + space + L + e + g + e + n + d + s + dot + e + x + e;
	string payloadPath = GetExePath() + "\\" + "dll name";

	std::system("cls");
	std::cout << "\tProcess Name: " << processName << endl;
	std::cout << "\tRelative Path: " << payloadPath << endl;

	std::wstring fatProcessName(processName.begin(), processName.end());

	std::unordered_set<DWORD> injectedProcesses;


	while (true) {
		std::cout << "Scanning";
		while (true) {
			SetConsoleTitleA(titleGen(rand() % 69 + 69).c_str());
			polymorphic();

			DWORD processId = FindProcessId(fatProcessName);
			if (processId && injectedProcesses.find(processId) == injectedProcesses.end()) {
				std::cout << "\n====================\n";
				std::cout << "Found a process to inject!" << endl;
				std::cout << "Process ID: " << processId << endl;
				std::cout << "Injecting Process: " << endl;

				if (InjectProcess(processId, payloadPath.c_str()) == 0) {
					std::cout << "Success!" << endl;
					std::cout << "The window will auto close in 3 sec!\n";
					Sleep(3000);
					return 0;
				}
				else {
					std::cout << "Error!" << endl;
				}
				std::cout << "====================\n";
				break;
			}
		}
	}
}

DWORD FindProcessId(const std::wstring& processName) {
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

long InjectProcess(DWORD ProcessId, const char* dllPath) {

	HANDLE hProcess, hThread, hSnap;
	DWORD stublen;
	PVOID LoadLibraryA_Addr, mem;

	THREADENTRY32 te32;
	CONTEXT ctx;

	// determine the size of the stub that we will insert
	stublen = (DWORD)stub_end - (DWORD)stub;
	cout << "Calculated the stub size to be: " << stublen << endl;


	// opening target process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!hProcess) {
		cout << "Failed to load hProcess with id " << ProcessId << endl;
		return -1;
	}

	// todo: identify purpose of this code
	te32.dwSize = sizeof(te32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);


	Thread32First(hSnap, &te32);
	cout << "Identifying a thread to hijack" << endl;
	while (Thread32Next(hSnap, &te32))
	{
		if (te32.th32OwnerProcessID == ProcessId)
		{
			cout << "Target thread found. TID: " << te32.th32ThreadID << endl;

			CloseHandle(hSnap);
			break;
		}
	}


	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, NULL, NULL, NULL);

	CLIENT_ID ClientId;
	ClientId.UniqueProcess = (PVOID)te32.th32OwnerProcessID;
	ClientId.UniqueThread = (PVOID)te32.th32ThreadID;

	// opening a handle to the thread that we will be hijacking
	NTSTATUS res = makesyscall<NTSTATUS>(0x2E, 0x01, 0x00, 0x00, "RtlInterlockedCompareExchange64",
		0x170, 0xC2, 0x10, 0x00)(
			&hThread, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
			&ObjectAttributes, &ClientId);

	if ((!NT_SUCCESS(res)) || (!hThread)) {
		cout << "Failed to open a handle to the thread " << te32.th32ThreadID << endl;
		return -1;
	}

	ctx.ContextFlags = CONTEXT_FULL;

	// now we suspend it.
	res = makesyscall<NTSTATUS>(
		0xBC, 0x01, 0x07, 0x00, "RtlInterlockedCompareExchange64", 0x170, 0xC2, 0x08,
		0x00)(hThread, NULL);

	// Get the thread context
	cout << "Getting the thread context" << endl;
	res = makesyscall<NTSTATUS>(0xF2, 0x00, 0x00, 0x00, "RtlInterlockedCompareExchange64", 0x170,
		0xC2, 0x08, 0x00)(hThread, &ctx);

	if (!NT_SUCCESS(res))
	{
		cout << "Unable to get the thread context of the target thread " << GetLastError() << endl;
		res = makesyscall<NTSTATUS>(
			0x6E, 0x00, 0x07, 0x00, "RtlInterlockedCompareExchange64", 0x170, 0xC2, 0x08,
			0x00)(hThread, NULL); // resume thread
		return -1;
	}

	cout << "Current EIP: " << ctx.Eip << endl;
	cout << "Current ESP: " << ctx.Esp << endl;

	cout << "Allocating memory in target process." << endl;
	mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!mem) {
		cout << "Unable to reserve memory in the target process." << endl;
		res = makesyscall<NTSTATUS>(
			0x6E, 0x00, 0x07, 0x00, "RtlInterlockedCompareExchange64", 0x170, 0xC2, 0x08,
			0x00)(hThread, NULL); // resume thread
		return -1;
	}

	cout << "Memory allocated at " << mem << endl;
	LoadLibraryA_Addr = LoadLibraryA;

	cout << "Writing shell code, LoadLibraryA address, and DLL path into target process" << endl;

	cout << "Writing out path buffer " << dllPath << endl;
	size_t dllPathLen = strlen(dllPath);

	WriteProcessMemory(hProcess, mem, &LoadLibraryA_Addr, sizeof(PVOID), NULL); // Write the address of LoadLibraryA into target process
	WriteProcessMemory(hProcess, (PVOID)((LPBYTE)mem + 4), stub, stublen, NULL); // Write the shellcode into target process
	WriteProcessMemory(hProcess, (PVOID)((LPBYTE)mem + 4 + stublen), dllPath, dllPathLen, NULL); // Write the DLL path into target process

	ctx.Esp -= 4; // Decrement esp to simulate a push instruction. Without this the target process will crash when the shellcode returns!
	WriteProcessMemory(hProcess, (PVOID)ctx.Esp, &ctx.Eip, sizeof(PVOID), NULL); // Write orginal eip into target thread's stack
	ctx.Eip = (DWORD)((LPBYTE)mem + 4); // Set eip to the injected shellcode

	cout << "new eip value: " << ctx.Eip << endl;
	cout << "new esp value: " << ctx.Esp << endl;

	cout << "Setting the thread context " << endl;

	res = makesyscall<NTSTATUS>(0x8B, 0x01, 0x00, 0x00, "RtlInterlockedCompareExchange64", 0x170, 0xC2, 0x08, 0x00)(hThread, &ctx);
	if (!NT_SUCCESS(res)) // Hijack the thread
	{
		cout << "Unable to SetThreadContext" << endl;
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		res = makesyscall<NTSTATUS>(
			0x6E, 0x00, 0x07, 0x00, "RtlInterlockedCompareExchange64", 0x170, 0xC2, 0x08,
			0x00)(hThread, NULL); // resume thread
		return -1;
	}

	res = makesyscall<NTSTATUS>(
		0x6E, 0x00, 0x07, 0x00, "RtlInterlockedCompareExchange64", 0x170, 0xC2, 0x08,
		0x00)(hThread, NULL); // resume thread

	cout << "Done." << endl;

	return 0;
}