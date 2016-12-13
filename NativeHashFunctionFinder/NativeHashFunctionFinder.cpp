/**
 * @file NativeHashFunctionFinder.cpp
 * @brief Locates Address of Native Function in Process Memory
 * Tested with GTA5 757.4
 * Based on a concept by Bucho
 * @author sfinktah
 * @version 0.0.3
 * @date 2016-07-04
 */
/* Copyright (c) 2016 - Sfinktah Bungholio LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#pragma warning(disable:4996)
#define PSAPI_VERSION 1
#define SUPPORT_64BIT_OFFSET
// #define DEOBFU
#define MAKE_IDAPYTHON_SCRIPT

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
#include <thread>
#include <time.h>
#include <vector>
#include <SDKDDKVer.h>
#include <TlHelp32.h>
#include <algorithm>
#include <psapi.h>
#include <Shlwapi.h>
#include "Libraries/distorm/include/distorm.h"
#include "Libraries/distorm/include/mnemonics.h"
#include "natives.h"
#include "../MemoryLib/MemoryLib.h"
#include "NativeHashFunctionFinder.h"
#include "Flow.h"
#include "MemoryShim.h"
#include "NativeDumpFile.h"
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Libraries/distorm/distorm.lib")
// Useful references for future development: http://atom0s.com/forums/viewtopic.php?f=5&t=4&sid=4c99acd92ec8836e72d6740c9dad02ca
/*

Steam Check Function:
48 83 ec ?? ff 15 ?? ?? ?? ?? 48 85 c0 74 2a ff 15 ?? ?? ?? ?? 48 8d 54 24 ?? 4c 8b 00 48 8b c8 41 ff 50 10



Base Address:
   
   7FF79AB3F785 - 9DF785 = 7FF79A160000
   7FF79AB3F785 + ffffffffff62087b = 7FF79A160000

   7FF79AB3F77E - 48 8D 15 7B0862FF     - lea rdx,[rip+0xffffffffff62087b] or RIP - 10352517 or RIP - 0x9DF785
   7FF79AB3F785 - 48 63 C1              - movsxd  rax,ecx
   7FF79AB3F788 - 48 8B 8C C2 A011B802  - mov    rcx,QWORD PTR [rdx+rax*8+0x2b811a0]
   7FF79AB3F790 - 48 85 C9              - test rcx,rcx
   7FF79AB3F793 - 74 19                 - je 7FF79AB3F7AE

   48 8D 15 7B 08 62 FF 48 63 C1
   48 8B 8C C2 A0 11 B8 02 48 85 C9 74 19

   BaseAddress: 48 8D 15 ?? ?? ?? ?? 48 63 C1 48 8B 8C C2 ?? ?? ?? ?? 48 85 C9 74 19
   GetPointerAddressA:                        48 8B 8C C2 ?? ?? ?? ?? 48 85 C9 74 19


   autoAssemble([[
   AOBSCANMODULE(LightsPTR,GTA5.exe,4C 89 0D xx xx xx xx 44 xx xx xx xx xx xx 8B 00 2B C1 48 8D)
   REGISTERSYMBOL(LightsPTR)
   ]])
   local addr = getAddress("LightsPTR")
   addr = addr + readInteger(addr + 3) + 7
   unregisterSymbol("LightsPTR")
   registerSymbol("LightsPTR", addr, true)

   autoAssemble([[
   AOBSCANMODULE(GetPointerAddressA,GTA5.exe,48 8B 8C C2 xx xx xx xx 48 85 C9 74 19)
   REGISTERSYMBOL(GetPointerAddressA)
   ]])
   local addr = getAddress("GetPointerAddressA")
   addr = addr + 4
   addr = readInteger(addr)
   addr = addr + getAddress("GTA5.exe")
   unregisterSymbol("GetPointerAddressA")
   registerSymbol("GetPointerAddressA", addr, true)

   autoAssemble([[
   AOBSCANMODULE(WorldPTR,GTA5.exe,48 8B 05 ? ? ? ? 45 ? ? ? ? 48 8B 48 08 48 85 C9 74 07)
   REGISTERSYMBOL(WorldPTR)
   ]])
   local addr = getAddress("WorldPTR")
   addr = addr + readInteger(addr + 3) + 7
   unregisterSymbol("WorldPTR")
   registerSymbol("WorldPTR", addr, true)

   autoAssemble([[
   AOBSCANMODULE(playersPTR,GTA5.exe,48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B CF)
   REGISTERSYMBOL(playersPTR)
   ]])
   local addr = getAddress("playersPTR")
   addr = addr + readInteger(addr + 3) + 7
   unregisterSymbol("playersPTR")
   registerSymbol("playersPTR", addr, true)

   <Description>"LockOnRange"</Description>
   <VariableType>Float</VariableType>
   <Address>WorldPTR</Address>
   <Offsets>
   <Offset>258</Offset>
   <Offset>20</Offset>
   <Offset>1098</Offset>
   <Offset>8</Offset>
   </Offsets>
*/


HANDLE hProcess;

// Retrieve the system error message for the last-error code
void ErrorExit(LPTSTR lpszFunction)
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("\n%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	_tprintf(TEXT("%s\n"), (LPCTSTR)lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}



// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS

__int64 GetBaseAddress(DWORD processId)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processId);

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod),
			&cbNeeded, LIST_MODULES_32BIT | LIST_MODULES_64BIT))
		{
			return (__int64)hMod;
		}
	}

	CloseHandle(hProcess);
	return 0;
}

DWORD GetProcessByName(WCHAR* name)
{
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process))
	{
		do
		{
			if (wcsstr(process.szExeFile, name) != NULL)
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	if (pid != 0)
	{
		return pid;
	}

	return NULL;
}


LPTSTR AddBaseDir(LPCTSTR pszPath) {
	static LPTSTR buf = new TCHAR[MAX_PATH];
	if (!GetModuleFileName(NULL, buf, MAX_PATH))                  ErrorExit(TEXT("GetModuleFileName(NULL)"));
	if (!PathRemoveFileSpec(buf)) 								  ErrorExit(TEXT("PathRemoveFileSpec"));
	TCHAR destination[100] = _T("Break Free");
	if (_tcscat_s(buf, MAX_PATH, pszPath))                        ErrorExit(TEXT("_tcscat_s"));
	return buf;
}






void* ReadMemory(LPCVOID lpBaseAddress, SIZE_T bufLen = 128) {
	static unsigned char* buf = new unsigned char[bufLen];
	static vector<unsigned char> vectorBuf;
	SIZE_T nRead = 0;
	// SIZE_T bufLen = 0x32;
	if (!ReadProcessMemory(hProcess, lpBaseAddress, buf, bufLen, &nRead))
		ErrorExit(TEXT("ReadProcessMemory"));

	return buf;
}

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (1000)
Flow flow;

int dis64(MemoryShim memory, int len, _OffsetType offset)
{

	_DInst di[40];
	unsigned int instructions_count = 0;
	_DecodedInst inst;

	_CodeInfo ci = {0};
	ci.code = memory.memoryAsBuffer();
	ci.codeLen = len;
	ci.codeOffset = offset;
	ci.dt = Decode64Bits;
	ci.features = DF_STOP_ON_FLOW_CONTROL & ~(DF_STOP_ON_CND_BRANCH | DF_STOP_ON_CMOV);
	
	flow.contents.clear();
	distorm_decompose(&ci, di, sizeof(di)/sizeof(di[0]), &instructions_count);

	// well, if instruction_count == 0, we won't enter the loop.
	for (unsigned int i = 0; i < instructions_count; i++) {
		if (di[i].flags == FLAG_NOT_DECODABLE) {
			printf("distorm: FLAG_NOT_DECODABLE\n");
			// handle instruction error!
			break;
		}
		// for (i = 0; i < di->size; i++) str_hex_b(str, ci->code[(unsigned int)(di->addr - ci->codeOffset + i)]);
		distorm_format(&ci, &di[i], &inst);

		if (di[i].opcode != I_JMP) {
			for (int j = 0; j < di[i].size; ++j) {
				flow.push_back(inst.offset + j, ci.code[(unsigned int)(di[i].addr - ci.codeOffset + j)]);
			}
		}
		// printf("%s %s\n", inst.mnemonic.p, inst.operands.p);
		printf("%0*I64x (%02d) %-24s %s%s%s\n",
			 ci.dt != Decode64Bits ? 8 : 16,
			 inst.offset,
			 inst.size,
			 (char*)inst.instructionHex.p,
			 (char*)inst.mnemonic.p,
			 inst.operands.length != 0 ? " " : "",
			 (char*)inst.operands.p);
	}

#if  0
	// Handling file.
	DWORD filesize, bytesread;

	// Buffer to disassemble.
	unsigned char *buf, *buf2;


	buf2 = buf = (unsigned char*)memory;
	filesize = bytesread = len;
	// printf("bits: %d\nfilename: %s\norigin: ", dt == Decode16Bits ? 16 : dt == Decode32Bits ? 32 : 64, "memory");
#ifdef SUPPORT_64BIT_OFFSET
	// if (dt != Decode64Bits) printf("%08I64x\n", offset);
	// else printf("%016I64x\n", offset);
#else
	printf("%08x\n", offset);
#endif
	// 00007ff7863a39f4 (05) e9e82e9a02               JMP 0x7ff788d468e1
	// 00007ff7863a39f9 (05) 488d642408               LEA RSP, [RSP + 0x8]
	// Decode the buffer at given offset (virtual address).
	while (1) {
		// If you get an unresolved external symbol linker error for the following line,
		// change the SUPPORT_64BIT_OFFSET in distorm.h.
		res = distorm_decode(offset, (const unsigned char*)buf, filesize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR) {
			// Null buffer? Decode type not 16/32/64?
			printf("Input error, halting!");

			return -4;
		}

		for (i = 0; i < decodedInstructionsCount; i++) {
#ifdef SUPPORT_64BIT_OFFSET
			printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
#else
			printf("%08x (%02d) %-24s %s%s%s\n", decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
#endif
			if (i > 0 && !strcmp((char*)decodedInstructions[i].mnemonic.p, "JMP")) {
				break;
			}
		}



		if (res == DECRES_SUCCESS) break; // All instructions were decoded.
		else if (decodedInstructionsCount == 0) break;

		// Synchronize:
		next = (unsigned long)(decodedInstructions[decodedInstructionsCount - 1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount - 1].size;
		// Advance ptr and recalc offset.
		buf += next;
		filesize -= next;
		offset += next;
	}

	// Release buffer
#endif

	return 0;
}

#ifdef MAKE_NATIVE_DUMP_FILE
NativeDumpFile nativeDumpFile;
#endif

#ifdef MAKE_IDAPYTHON_SCRIPT
FILE *fPythonScript;
#endif


intptr_t baseAddress;
SYSTEM_INFO si;
int setupProcess() {

	DWORD PPID = GetProcessByName(TEXT("GTA5"));
	if (!PPID) {
		printf("Failed to GetProcessByName(GTA5)\n");
		exit(1);
	}
	else {
		printf("Found GTA5.exe, PID: %lu\n", PPID);
	}

	baseAddress = GetBaseAddress(PPID);
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, PPID);
	if (!hProcess) 
		ErrorExit(TEXT("OpenProcess"));
	return 1;
}

// This is going to be terribly ineffecient, and just start the whole thing off from the start every time.
int getNativeFunction(__int64 hash, char* name)
{
	// hash = 0xC834A7C58DEB59B4;

	
	printf("Scanning process for %s hash 0x%016llx\n\n", name, hash);
	auto addr_min = (__int64)si.lpMinimumApplicationAddress;
	auto addr_max = (__int64)si.lpMaximumApplicationAddress;
	static auto min_found = addr_max;

	// This may speed up matters a great deal (or it may break things, remove 
	// these three lines if you seem to be missing hashes)
	if (min_found < addr_max) {
		addr_min = min_found - 0x5000000;
	}
	auto found = 0;
	// addr_min = 0x20fb194c000;
	// 20FB2c68000
	// 27f92213338
	// 22fde5ed128 -
	// 20fb194c000
	//  2800000000
	// Loop the pages of memory of the application.. 
	while (addr_min < addr_max && !found)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (!VirtualQueryEx(hProcess, (LPCVOID)addr_min, &mbi, sizeof(mbi)))
			ErrorExit(TEXT("VirtualQueryEx"));

		// Determine if we have access to the page.. 
		if (mbi.State == MEM_COMMIT && ((mbi.Protect & PAGE_GUARD) == 0) && ((mbi.Protect & PAGE_NOACCESS) == 0))
		{
			// 
			// Below are flags about the current region of memory. If you want to specifically scan for only 
			// certain things like if the area is writable, executable, etc. you can use these flags to prevent 
			// reading non-desired protection types. 
			// 

			auto isCopyOnWrite = ((mbi.Protect & PAGE_WRITECOPY) != 0 || (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0);
			auto isExecutable = ((mbi.Protect & PAGE_EXECUTE) != 0 || (mbi.Protect & PAGE_EXECUTE_READ) != 0 || (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 || (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0);
			auto isWritable = ((mbi.Protect & PAGE_READWRITE) != 0 || (mbi.Protect & PAGE_WRITECOPY) != 0 || (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 || (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0);

			// Dump the region into a memory block.. 
			// TODO: Have it read directly into a vector
			auto dump = new unsigned char[mbi.RegionSize + 1];
			memset(dump, 0x00, mbi.RegionSize + 1);

			// printf("\r0x%llx: %04x", (__int64)mbi.BaseAddress, mbi.Protect); // mbi.Protect & 0x100);
			if (!ReadProcessMemory(hProcess, mbi.BaseAddress, dump, mbi.RegionSize, NULL))
				ErrorExit(TEXT("ReadProcessMemory")); // "Failed to read memory of location : %08X\n", mbi.BaseAddress);

			__int64 Address = (__int64)mbi.BaseAddress;

			
#if 1
			for (SIZE_T x = 0; x < mbi.RegionSize - 8; x += 4, Address += 4)
			{
				if (*(__int64*)(dump + x) == hash) 
				{
					found++;
					// Address == ((__int64)mbi.BaseAddress + x)
					if (Address < min_found) {
						min_found = Address;
					}
					printf_s("\nFound hash at address: 0x%12llx (lowest address: 0x%12llx )\n", Address, min_found);
					if (x >= 0x40) {
						__int64 offset = *(__int64*)(dump + x - 0x40);
						printf_s("Pointer to Native Function is at: 0x%12llx\n", Address - 0x40);
						printf_s("Native Function Address: 0x %12llx\n", offset);
						if (!offset) break;
#ifdef MAKE_NATIVE_DUMP_FILE
						nativeDumpFile.natives[nativeDumpFile.native_count].hash = hash;
						nativeDumpFile.natives[nativeDumpFile.native_count].func_offset = offset; /*  - 0x7FF79A160000 + 0x140000000; */
						nativeDumpFile.native_count++;
#endif
#ifdef MAKE_IDAPYTHON_SCRIPT


						fprintf( fPythonScript, "MakeNativeFunction( 0x%012llx, \"%s\" )\n", offset, name );
#endif
						/*
						BOOL WINAPI ReadProcessMemory(
						  _In_  HANDLE  hProcess,
						  _In_  LPCVOID lpBaseAddress,
						  _Out_ LPVOID  lpBuffer,
						  _In_  SIZE_T  nSize,
						  _Out_ SIZE_T  *lpNumberOfBytesRead
						);	*/

						/*
						 * SIZE_T nRead = 0;
                         * x32;
						 * unsigned char* buf = new unsigned char[bufLen];
						 * printf("Attempting to read native function memory...\n");
						 * if (!ReadProcessMemory(hProcess, (void *)offset, buf, bufLen, &nRead))
						 *     ErrorExit(TEXT("ReadProcessMemory"));
						 */
#ifdef DEOBFU
						int bufLen = 128;
						DWORD64 jmpLocation = 0;
						unsigned char *buf;
						MemoryShim memory;
						memory.setAutoLoader([&](intptr_t offset) {
							unsigned char *buf = (unsigned char *)ReadMemory((void *)offset, bufLen);
							return std::vector<unsigned char>(buf, buf+bufLen);
						});
						
						while (true) {
							buf = memory.readMemory(offset, bufLen);
							std::vector<unsigned char> data = memory.getVector();
							dis64(memory, (int)bufLen, offset);
							break;
						}
#endif
					}
					else {
						printf("\nNative Function Address is on previous page... woops!");
					}
					break;
				}
				if (found) break;
			}
#endif

			// Cleanup the memory dump.. 
			delete[] dump;
		}

		// Step the current address by this regions size.. 
		if (found) break;
		addr_min += mbi.RegionSize;
	}

	printf("\n\n");
	return 0;
}

int main(int argc, char **argv) {
	unsigned long dver = 0;
	dver = distorm_version();
	printf("Disassembled with diStorm version: %d.%d.%d\n\n", (dver >> 16), ((dver) >> 8) & 0xff, dver & 0xff);


#ifdef MAKE_NATIVE_DUMP_FILE
	nativeDumpFile.magic = 0x5654414E; // 'NATV'
	nativeDumpFile.version = 1;       // version of dump
	nativeDumpFile.native_count = 0;   // number
#endif
	setupProcess();
#ifdef MAKE_IDAPYTHON_SCRIPT
	CopyFile(AddBaseDir(TEXT("\\native-hashes-template.py")), TEXT("native-hashes.py"), 0);
	fopen_s( &fPythonScript, "native-hashes.py", "a+" );
	fprintf( fPythonScript, "\n__gtaBaseAddress = 0x%012llx\n", baseAddress );
#endif

	for_each(ALLNATIVES.begin(), ALLNATIVES.end(), [](nativeStruct n) { getNativeFunction(n.hash, n.name); });
#ifdef MAKE_NATIVE_DUMP_FILE
	FILE *fw = fopen("nativeDumpFile.bin", "wb");
	fwrite(&nativeDumpFile, sizeof(nativeDumpFile), 1, fw);
	fclose(fw);
#endif
#ifdef MAKE_IDAPYTHON_SCRIPT
	fclose( fPythonScript );
#endif
}
