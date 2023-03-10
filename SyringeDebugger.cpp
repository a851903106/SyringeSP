#include "SyringeDebugger.h"

#include "CRC32.h"
#include "FindFile.h"
#include "Handle.h"
#include "Log.h"
#include "Support.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <memory>
#include <numeric>

#include <DbgHelp.h>

using namespace std;
std::vector<std::string> SyringeDebugger::IgnoredDlls{};
//TODO : Other Type of hook supports !

void SyringeDebugger::DebugProcess(std::string_view const arguments)
{
	STARTUPINFO startupInfo{ sizeof(startupInfo) };

	SetEnvironmentVariable("_NO_DEBUG_HEAP", "1");

	auto command_line = '"' + exe + "\" ";
	command_line += arguments;

	if (CreateProcess(
		exe.c_str(), command_line.data(), nullptr, nullptr, false,
		DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
		nullptr, nullptr, &startupInfo, &pInfo) == FALSE)
	{
		throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
	}
}

bool SyringeDebugger::PatchMem(void* address, void const* buffer, DWORD size)
{
	return (WriteProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

bool SyringeDebugger::ReadMem(void const* address, void* buffer, DWORD size)
{
	return (ReadProcessMemory(pInfo.hProcess, address, buffer, size, nullptr) != FALSE);
}

VirtualMemoryHandle SyringeDebugger::AllocMem(void* address, size_t size)
{
	if (VirtualMemoryHandle res{ pInfo.hProcess, address, size }) {
		return res;
	}

	throw_lasterror_or(ERROR_ERRORS_ENCOUNTERED, exe);
}

bool SyringeDebugger::SetBP(void* address)
{
	// save overwritten code and set INT 3
	if (auto& opcode = Breakpoints[address].original_opcode; opcode == 0x00) {
		auto const buffer = INT3;
		ReadMem(address, &opcode, 1);
		return PatchMem(address, &buffer, 1);
	}

	return true;
}

DWORD __fastcall SyringeDebugger::RelativeOffset(void const* pFrom, void const* pTo)
{
	auto const from = reinterpret_cast<DWORD>(pFrom);
	auto const to = reinterpret_cast<DWORD>(pTo);

	return to - from;
}

DWORD SyringeDebugger::HandleException(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	auto const exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

	if (exceptCode == EXCEPTION_BREAKPOINT)
	{
		auto& threadInfo = Threads[dbgEvent.dwThreadId];
		HANDLE currentThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(currentThread, &context);

		// entry breakpoint
		if (bEntryBP)
		{
			bEntryBP = false;
			return DBG_CONTINUE;
		}

		// fix single step repetition issues
		if (context.EFlags & 0x100)
		{
			auto const buffer = INT3;
			context.EFlags &= ~0x100;
			PatchMem(threadInfo.lastBP, &buffer, 1);
		}

		// load DLLs and retrieve proc addresses
		if (!bDLLsLoaded)
		{
			// restore
			PatchMem(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1);

			if (loop_LoadLibrary == v_AllHooks.end())
			{
				loop_LoadLibrary = v_AllHooks.begin();
			}
			else
			{
				auto const& hook = *loop_LoadLibrary;
				ReadMem(&GetData()->ProcAddress, &hook->proc_address, 4);

				if (!hook->proc_address) {
					Log::WriteLine(
						__FUNCTION__ ": Could not retrieve ProcAddress for: %s "
						"- %s", hook->lib, hook->proc);
				}

				++loop_LoadLibrary;
			}

			if (loop_LoadLibrary != v_AllHooks.end())
			{
				auto const& hook = *loop_LoadLibrary;
				PatchMem(&GetData()->LibName, hook->lib, MaxNameLength);
				PatchMem(&GetData()->ProcName, hook->proc, MaxNameLength);

				context.Eip = reinterpret_cast<DWORD>(&GetData()->LoadLibraryFunc);
			}
			else
			{
				Log::WriteLine(__FUNCTION__ ": Finished retrieving proc addresses.");
				bDLLsLoaded = true;

				context.Eip = reinterpret_cast<DWORD>(pcEntryPoint);
			}

			// single step mode
			context.EFlags |= 0x100;
			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			threadInfo.lastBP = exceptAddr;

			return DBG_CONTINUE;
		}

		if (exceptAddr == pcEntryPoint)
		{
			if (!bHooksCreated)
			{
				Log::WriteLine(__FUNCTION__ ": Creating code hooks.");

				constexpr static BYTE const code_call[] =
				{
					0x60, 0x9C, // PUSHAD, PUSHFD
					0x68, INIT, INIT, INIT, INIT, // PUSH HookAddress
					0x54, // PUSH ESP
					0xE8, INIT, INIT, INIT, INIT, // CALL ProcAddress
					0x83, 0xC4, 0x08, // ADD ESP, 8
					0xA3, INIT, INIT, INIT, INIT, // MOV ds:ReturnEIP, EAX
					0x9D, 0x61, // POPFD, POPAD
					0x83, 0x3D, INIT, INIT, INIT, INIT, 0x00, // CMP ds:ReturnEIP, 0
					0x74, 0x06, // JZ .proceed
					0xFF, 0x25, INIT, INIT, INIT, INIT, // JMP ds:ReturnEIP
				};

				constexpr static BYTE const jmp_back[] = { 0xE9, INIT, INIT, INIT, INIT };
				constexpr static BYTE const jmp[] = { 0xE9, INIT, INIT, INIT, INIT };

				std::vector<BYTE> code{};
				int acount = 0;

				for (auto& [entry, breaks] : Breakpoints)
				{
					++acount;
					if (entry == nullptr || entry == pcEntryPoint)
					{
						continue;
					}				

					auto const [count, overridden] = std::accumulate(breaks.hooks.cbegin(), breaks.hooks.cend(), std::make_pair(0u, 0u), [](auto acc, auto const& hook)
					{
							if (hook.proc_address)
							{
								if (acc.second < hook.num_overridden) {
									acc.second = hook.num_overridden;
								}
								acc.first++;
							}

						return acc;
					});

					if (!count)
					{
						continue;
					}

					auto const sz = (count * sizeof(code_call))
						+ sizeof(jmp_back) + overridden;

					code.resize(sz);
					auto p_code = code.data();

					breaks.p_caller_code = AllocMem(nullptr, sz);
					auto const base = breaks.p_caller_code.get();

					// write caller code

					for (auto const& hook : breaks.hooks)
					{
						Log::WriteLine(__FUNCTION__ ": [%s - %d][0x%x = %s , %d] Final Size %d.", hook.lib, acount, hook.hookaddr, hook.proc, hook.num_overridden, sz);

						if (hook.proc_address)
						{
							ApplyPatch(p_code, code_call); // code
							ApplyPatch(p_code + 0x03, entry); // PUSH HookAddress

							auto const rel = RelativeOffset(
								base + (p_code - code.data() + 0x0D), hook.proc_address);
							ApplyPatch(p_code + 0x09, rel); // CALL

							auto const pdReturnEIP = &GetData()->ReturnEIP;
							ApplyPatch(p_code + 0x11, pdReturnEIP); // MOV
							ApplyPatch(p_code + 0x19, pdReturnEIP); // CMP
							ApplyPatch(p_code + 0x22, pdReturnEIP); // JMP ds:ReturnEIP

							p_code += sizeof(code_call);
						}
					}

					// write overridden bytes
					if (overridden)
					{
						ReadMem(entry, p_code, overridden);
						p_code += overridden;
					}

					// write the jump back
					auto const rel = RelativeOffset(
						base + (p_code - code.data() + 0x05),
						static_cast<BYTE*>(entry) + 0x05);
					ApplyPatch(p_code, jmp_back);
					ApplyPatch(p_code + 0x01, rel);

					PatchMem(base, code.data(), code.size());

					// dump

				    //Log::WriteLine("Call dump for 0x%08X at 0x%08X:", entry, base);

					code.resize(sz);
					ReadMem(breaks.p_caller_code, code.data(), sz);
					/*
										std::string dump_str{ "\t\t" };
										for(auto const& byte : code) {
											char buffer[0x10];
											sprintf(buffer, "%02X ", byte);
											dump_str += buffer;
										}

										Log::WriteLine(dump_str.c_str());
										Log::WriteLine();*/

										// patch original code
					auto const p_original_code = static_cast<BYTE*>(entry);

					auto const rel2 = RelativeOffset(p_original_code + 5, base);
					code.assign(std::max(overridden, sizeof(jmp)), NOP);
					ApplyPatch(code.data(), jmp);
					ApplyPatch(code.data() + 0x01, rel2);

					PatchMem(p_original_code, code.data(), code.size());
				}

				Log::WriteLine(__FUNCTION__" :CodeSize After [%d]", code.size());
				Log::Flush();

				bHooksCreated = true;
			}

			/*
			// restore*/
			PatchMem(exceptAddr, &Breakpoints[exceptAddr].original_opcode, 1);

			// single step mode
			context.EFlags |= 0x100;
			--context.Eip;

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			threadInfo.lastBP = exceptAddr;

			return DBG_CONTINUE;
		}
		else
		{
			// could be a Debugger class breakpoint to call a patching function!

			context.ContextFlags = CONTEXT_CONTROL;
			SetThreadContext(currentThread, &context);

			return DBG_EXCEPTION_NOT_HANDLED;
		}
	}
	else if (exceptCode == EXCEPTION_SINGLE_STEP)
	{
		auto const buffer = INT3;
		auto const& threadInfo = Threads[dbgEvent.dwThreadId];
		PatchMem(threadInfo.lastBP, &buffer, 1);

		HANDLE hThread = threadInfo.Thread;
		CONTEXT context;

		context.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &context);

		context.EFlags &= ~0x100;

		context.ContextFlags = CONTEXT_CONTROL;
		SetThreadContext(hThread, &context);

		return DBG_CONTINUE;
	}
	else
	{
		//	Log::WriteLine(
		//		__FUNCTION__ ": Exception (Code: 0x%08X at 0x%08X)!", exceptCode,
		//		exceptAddr);

		if (!bAVLogged)
		{
			Log::WriteLine(__FUNCTION__ ": ACCESS VIOLATION at 0x%08X!", exceptAddr);
			auto const& threadInfo = Threads[dbgEvent.dwThreadId];
			HANDLE currentThread = threadInfo.Thread;

			char const* access = nullptr;
			switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[0])
			{
			case 0: access = "read from"; break;
			case 1: access = "write to"; break;
			case 8: access = "execute"; break;
			}

			Log::WriteLine("\tThe process tried to %s 0x%08X.",
				access,
				dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]);

			CONTEXT context;
			context.ContextFlags = CONTEXT_FULL;
			GetThreadContext(currentThread, &context);

			Log::WriteLine();
			Log::WriteLine("Registers:");
			Log::WriteLine("\tEAX = 0x%08X\tECX = 0x%08X\tEDX = 0x%08X",
				context.Eax, context.Ecx, context.Edx);
			Log::WriteLine("\tEBX = 0x%08X\tESP = 0x%08X\tEBP = 0x%08X",
				context.Ebx, context.Esp, context.Ebp);
			Log::WriteLine("\tESI = 0x%08X\tEDI = 0x%08X\tEIP = 0x%08X",
				context.Esi, context.Edi, context.Eip);
			Log::WriteLine();

			Log::WriteLine("\tStack dump:");
			auto const esp = reinterpret_cast<DWORD*>(context.Esp);
			for (auto p = esp; p < &esp[0x100]; ++p) {
				DWORD dw;
				if (ReadMem(p, &dw, 4)) {
					Log::WriteLine("\t0x%08X:\t0x%08X", p, dw);
				}
				else {
					Log::WriteLine("\t0x%08X:\t(could not be read)", p);
				}
			}
			Log::WriteLine();

			//Log::WriteLine("Making crash dump:\n");
			//MINIDUMP_EXCEPTION_INFORMATION expParam;
			//expParam.ThreadId = dbgEvent.dwThreadId;
			//EXCEPTION_POINTERS ep;
			//ep.ExceptionRecord = const_cast<PEXCEPTION_RECORD>(&dbgEvent.u.Exception.ExceptionRecord);
			//ep.ContextRecord = &context;
			//expParam.ExceptionPointers = &ep;
			//expParam.ClientPointers = FALSE;

			//wchar_t filename[MAX_PATH];
			//wchar_t path[MAX_PATH];
			//SYSTEMTIME time;

			//GetLocalTime(&time);
			//GetCurrentDirectoryW(MAX_PATH, path);

			//swprintf(filename, MAX_PATH, L"%s\\syringe.crashed.%04u%02u%02u-%02u%02u%02u.dmp",
			//	path, time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

			//HANDLE dumpFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
			//	FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, nullptr);

			//MINIDUMP_TYPE type = (MINIDUMP_TYPE)MiniDumpWithFullMemory;

			//MiniDumpWriteDump(pInfo.hProcess, dbgEvent.dwProcessId, dumpFile, type, &expParam, nullptr, nullptr);
			//CloseHandle(dumpFile);

			//Log::WriteLine("Crash dump generated.\n");

			bAVLogged = true;
		}

		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_CONTINUE;
}

void SyringeDebugger::Run(std::string_view const arguments)
{
	constexpr auto AllocDataSize = sizeof(AllocData);

	Log::WriteLine(
		__FUNCTION__ ": Running process to debug. cmd = \"%s %.*s\"",
		exe.c_str(), printable(arguments));
	DebugProcess(arguments);

	Log::WriteLine(__FUNCTION__ ": Allocating 0x%u bytes...", AllocDataSize);
	pAlloc = AllocMem(nullptr, AllocDataSize);

	Log::WriteLine(__FUNCTION__ ": pAlloc = 0x%08X", pAlloc.get());

	// write DLL loader code
	Log::WriteLine(__FUNCTION__ ": Writing DLL loader & caller code...");

	static constexpr BYTE const cLoadLibrary[] =
	{
		0x50, // push eax
		0x51, // push ecx
		0x52, // push edx
		0x68, INIT, INIT, INIT, INIT, // push offset pdLibName
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pImLoadLibrary
		0x85, 0xC0, // test eax, eax
		0x74, 0x0C, // jz
		0x68, INIT, INIT, INIT, INIT, // push offset pdProcName
		0x50, // push eax
		0xFF, 0x15, INIT, INIT, INIT, INIT, // call pdImGetProcAddress
		0xA3, INIT, INIT, INIT, INIT, // mov pdProcAddress, eax
		0x5A, // pop edx
		0x59, // pop ecx
		0x58, // pop eax
		INT3, NOP // int3 and some padding
	};

	std::array<BYTE, AllocDataSize> data;
	static_assert(AllocData::CodeSize >= sizeof(cLoadLibrary) , "Invalid Size !");
	ApplyPatch(data.data(), cLoadLibrary);
	ApplyPatch(data.data() + 0x04, &GetData()->LibName);
	ApplyPatch(data.data() + 0x0A, pImLoadLibrary);
	ApplyPatch(data.data() + 0x13, &GetData()->ProcName);
	ApplyPatch(data.data() + 0x1A, pImGetProcAddress);
	ApplyPatch(data.data() + 0x1F, &GetData()->ProcAddress);
	PatchMem(pAlloc, data.data(), data.size());

	Log::WriteLine(__FUNCTION__ ": pcLoadLibrary = 0x%08X", &GetData()->LoadLibraryFunc);

	// breakpoints for DLL loading and proc address retrieving
	bDLLsLoaded = false;
	bHooksCreated = false;
	loop_LoadLibrary = v_AllHooks.end();

	// set breakpoint
	SetBP(pcEntryPoint); //add break point list

	DEBUG_EVENT dbgEvent;
	ResumeThread(pInfo.hThread);

	bAVLogged = false;

	Log::WriteLine(__FUNCTION__ ": Entering debug loop...");

	auto exit_code = static_cast<DWORD>(-1);

	for (;;)
	{
		WaitForDebugEvent(&dbgEvent, INFINITE);

		DWORD continueStatus = DBG_CONTINUE;
		bool wasBP = false;

		switch (dbgEvent.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			pInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
			pInfo.dwThreadId = dbgEvent.dwProcessId;
			pInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
			pInfo.dwThreadId = dbgEvent.dwThreadId;
			Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo.hThread);
			CloseHandle(dbgEvent.u.CreateProcessInfo.hFile);
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			Threads.emplace(dbgEvent.dwThreadId, dbgEvent.u.CreateThread.hThread);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			if (auto const it = Threads.find(dbgEvent.dwThreadId); it != Threads.end())
			{
				it->second.Thread.release();
				Threads.erase(it);
			}
			break;

		case EXCEPTION_DEBUG_EVENT:
			continueStatus = HandleException(dbgEvent);
			wasBP = (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			CloseHandle(dbgEvent.u.LoadDll.hFile);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
			exit_code = dbgEvent.u.ExitProcess.dwExitCode;
			break;
		}
		else if (dbgEvent.dwDebugEventCode == RIP_EVENT) {
			break;
		}

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
	}

	CloseHandle(pInfo.hProcess);

	Log::WriteLine(
		__FUNCTION__ ": Done with exit code %X (%u).", exit_code, exit_code);
	Log::WriteLine();
}

void SyringeDebugger::RemoveBP(LPVOID const address, bool const restoreOpcode)
{
	if (auto const i = Breakpoints.find(address); i != Breakpoints.end())
	{
		if (restoreOpcode)
		{
			PatchMem(address, &i->second.original_opcode, 1);
			//MessageBoxA(
			//	nullptr, "Syringe Attempt to Remove Break points",
			//	"gamemd.exe", MB_OK | MB_ICONINFORMATION);
		}

		Breakpoints.erase(i);
	}
}

void SyringeDebugger::RetrieveInfo()
{
	Log::WriteLine(
		__FUNCTION__ ": Retrieving info from the executable file...");

	try {
		PortableExecutable pe{ exe };
		auto const dwImageBase = pe.GetImageBase();

		// creation time stamp
		dwTimeStamp = pe.GetPEHeader().FileHeader.TimeDateStamp;

		// entry point
		pcEntryPoint = reinterpret_cast<void*>(dwImageBase + pe.GetPEHeader().OptionalHeader.AddressOfEntryPoint);

		// get imports
		pImLoadLibrary = nullptr;
		pImGetProcAddress = nullptr;

		for (auto const& import : pe.GetImports()) {
			if (_strcmpi(import.Name.c_str(), "KERNEL32.DLL") == 0) {
				for (auto const& thunk : import.vecThunkData) {
					if (_strcmpi(thunk.Name.c_str(), "GETPROCADDRESS") == 0) {
						pImGetProcAddress = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					}
					else if (_strcmpi(thunk.Name.c_str(), "LOADLIBRARYA") == 0) {
						pImLoadLibrary = reinterpret_cast<void*>(dwImageBase + thunk.Address);
					}
				}
			}
		}
	}
	catch (...) {
		Log::WriteLine(__FUNCTION__ ": Failed to open the executable!");

		throw;
	}

	if (!pImGetProcAddress || !pImLoadLibrary) {
		Log::WriteLine(
			__FUNCTION__ ": ERROR: Either a LoadLibraryA or a GetProcAddress "
			"import could not be found!");

		throw_lasterror_or(ERROR_PROC_NOT_FOUND, exe);
	}

	// read meta information: size and checksum
	if (ifstream is{ exe, ifstream::binary })
	{
		is.seekg(0, ifstream::end);
		dwExeSize = static_cast<DWORD>(is.tellg());
		is.seekg(0, ifstream::beg);

		CRC32 crc;
		char buffer[0x1000];
		while (auto const read = is.read(buffer, std::size(buffer)).gcount())
		{
			crc.compute(buffer, read);
		}
		dwExeCRC = crc.value();
	}

	Log::WriteLine(__FUNCTION__ ": Executable information successfully retrieved.");
	Log::WriteLine("\texe = %s", exe.c_str());
	Log::WriteLine("\tpImLoadLibrary = 0x%08X", pImLoadLibrary);
	Log::WriteLine("\tpImGetProcAddress = 0x%08X", pImGetProcAddress);
	Log::WriteLine("\tpcEntryPoint = 0x%08X", pcEntryPoint);
	Log::WriteLine("\tdwExeSize = 0x%08X", dwExeSize);
	Log::WriteLine("\tdwExeCRC = 0x%08X", dwExeCRC);
	Log::WriteLine("\tdwTimestamp = 0x%08X", dwTimeStamp);
	Log::WriteLine();

	Log::WriteLine(__FUNCTION__ ": Opening %s to determine imports.", exe.c_str());

	//MessageBoxA(
	//	nullptr, "Opening gamemd to determine imports.",
	//	__FUNCTION__, MB_OK | MB_ICONINFORMATION);
}

void SyringeDebugger::FindDLLs()
{
	Breakpoints.clear();
	HookBuffer buffer_Inj;
	HookBuffer buffer_Override;

	for (auto file = FindFile("*.dll"); file; ++file) {
		std::string_view const fn(file->cFileName);

		//Log::WriteLine(
		//	__FUNCTION__ ": Potential DLL: \"%.*s\"", printable(fn));

		try {
			PortableExecutable const DLL{ fn };
			HookBuffer buffer;

			bool canLoad = false;
			if (auto const hooks = DLL.FindSection(".syhks00")) {
				canLoad = ParseHooksSection(DLL, *hooks, buffer);
			}

			if (canLoad) {
				Log::WriteLine(
					__FUNCTION__ ": Recognized DLL: \"%.*s\"", printable(fn));

				const auto  excludeInj = ".exinj";
				if (!ParseInjFileHooks(fn, buffer_Inj , excludeInj)) {
					Log::WriteLine(
						__FUNCTION__ ": Failed Parsing DLL.exinj: \"%.*s\"", printable(fn));
				}

				if (auto const hooks = DLL.FindSection(".syhks01")) {
					if(ParseOverrideHooksSection(DLL, *hooks, buffer_Inj , buffer_Override))
					Log::WriteLine(
						__FUNCTION__ ": Found Override Hook Section : \"%.*s\"", printable(fn));
				}

				if (auto const res = Handshake(
					DLL.GetFilename(), static_cast<int>(buffer.count),
					buffer.checksum.value()))
				{
					canLoad = res;
				}
				else if (auto const hosts = DLL.FindSection(".syexe00")) {
					canLoad = CanHostDLL(DLL, *hosts);
				}
			}

			if (canLoad) {
				for (auto const& it : buffer.hooks) {
					auto const eip = it.first;
					auto& h = Breakpoints[eip];
					h.p_caller_code.clear();
					h.original_opcode = 0x00;
					h.hooks.insert(
						h.hooks.end(), it.second.begin(), it.second.end());
				}
			}
			else if (!buffer.hooks.empty()) {
				Log::WriteLine(
					__FUNCTION__ ": DLL load was prevented: \"%.*s\"",
					printable(fn));
			}
		}
		catch (...) {
			//Log::WriteLine(
			//	__FUNCTION__ ": DLL Parse failed: \"%.*s\"", printable(fn));
		}
	}

	// summarize all hooks
	v_AllHooks.clear();
	for (auto& it : Breakpoints)
	{
		for (size_t i = 0; i < it.second.hooks.size(); ++i)
		{
			auto& nBreakHook = it.second.hooks.at(i);

			for (auto& nIgnoreData : buffer_Inj.hooks) {
				auto& nReplace = buffer_Override.hooks.at(nIgnoreData.first);
				int iPos_buffer_internal = 0;

				for (auto& nVec : nIgnoreData.second) {

					if ((_strcmpi(nBreakHook.lib, nVec.lib) == 0) && //same dll
						nBreakHook.hookaddr == nVec.hookaddr)// same address
						//&& (_strcmpi(i->proc , nVec.proc) == 0)
						//&& i->num_overridden == i->num_overridden
					{
						Log::WriteLine(__FUNCTION__ ": hook [%s][0x%x = %s , %d] Removed .", nBreakHook.lib, nBreakHook.hookaddr, nBreakHook.proc, nBreakHook.num_overridden);
						auto& nVecHere = nReplace.at(iPos_buffer_internal);
						nBreakHook = nVecHere;
						Log::WriteLine(__FUNCTION__ ": hook [%s][0x%x = %s , %d] Re-Applied .", nVecHere.lib, nVecHere.hookaddr, nVecHere.proc, nVecHere.num_overridden);
					}
					++iPos_buffer_internal;
				}
			}

			v_AllHooks.push_back(&nBreakHook);
		}
	}



	Log::WriteLine(__FUNCTION__ ": Done (%d hooks added).", v_AllHooks.size());
	Log::WriteLine();
}

bool SyringeDebugger::ParseInjFileHooks(
	std::string_view const lib, HookBuffer& hooks , const char* extension)
{
	auto const inj = std::string(lib) + extension;

	if (auto const file = FileHandle(_fsopen(inj.c_str(), "r", _SH_DENYWR))) {
		Log::WriteLine(__FUNCTION__ ": %s %s file Found , Parsing." , lib , extension);

		constexpr auto Size = 0x100;
		char line[Size];
		while (fgets(line, Size, file)) {
			if (*line != ';' && *line != '\r' && *line != '\n') {
				void* eip = nullptr;
				auto n_over = 0u;
				char func[MaxNameLength];
				func[0] = '\0';
				// parse the line (length is optional, defaults to 0)
				if (sscanf_s(
					line, "%p = %[^ \t;,\r\n] , %x", &eip, func,
					static_cast<unsigned int>(MaxNameLength), &n_over) >= 2)
				{
					//Log::WriteLine(__FUNCTION__ ": [%s]Hook, %x=%s, %x", lib.data(), eip, func, n_over);
					hooks.add(eip, lib, func, static_cast<size_t>(n_over));
				}
			}
		}

		return true;
	}

	return false;
}

bool SyringeDebugger::CanHostDLL(
	PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hosts) const
{
	constexpr auto const Size = sizeof(hostdecl);
	auto const base = DLL.GetImageBase();

	auto const begin = hosts.PointerToRawData;
	auto const end = begin + hosts.SizeOfRawData;

	std::string hostName;
	for (auto ptr = begin; ptr < end; ptr += Size) {
		hostdecl h;
		if (DLL.ReadBytes(ptr, Size, &h)) {
			if (h.hostNamePtr) {
				auto const rawNamePtr = DLL.VirtualToRaw(h.hostNamePtr - base);
				if (DLL.ReadCString(rawNamePtr, hostName)) {
					hostName += ".exe";
					if (!_strcmpi(hostName.c_str(), exe.c_str())) {
						return true;
					}
				}
			}
		}
		else {
			break;
		}
	}
	return false;
}

bool SyringeDebugger::ParseHooksSection(
	PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hooks,
	HookBuffer& buffer)
{
	constexpr auto const Size = sizeof(hookdecl);
	auto const base = DLL.GetImageBase();
	auto const filename = std::string_view(DLL.GetFilename());

	auto const begin = hooks.PointerToRawData;
	auto const end = begin + hooks.SizeOfRawData;

	std::string hookName{};
	hookName.reserve(0x800);

	for (auto ptr = begin; ptr < end; ptr += Size) {
		hookdecl h{};
		if (DLL.ReadBytes(ptr, Size, &h)) {
			// msvc linker inserts arbitrary padding between variables that come
			// from different translation units
			if (h.hookNamePtr) {
				auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
				if (DLL.ReadCString(rawNamePtr, hookName)) {
					//Log::WriteLine(__FUNCTION__ ": [%s]Hook, %x=%s, %x", DLL.GetFilename(), h.hookAddr, hookName.c_str(), h.hookSize);
					buffer.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize);
				}
			}
		}
		else {
			Log::WriteLine(__FUNCTION__ ": Bytes read failed");
			return false;
		}
	}

	return true;
}

bool SyringeDebugger::ParseOverrideHooksSection(
	PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hooks,
	HookBuffer& overriderBuffer , HookBuffer& supposehook)
{
	constexpr auto const Size = sizeof(hookdecl);
	auto const base = DLL.GetImageBase();
	auto const filename = std::string_view(DLL.GetFilename());

	auto const begin = hooks.PointerToRawData;
	auto const end = begin + hooks.SizeOfRawData;

	std::string hookName{};
	hookName.reserve(0x800);

	std::string moduleName{};
	moduleName.reserve(0x800);

	for (auto ptr = begin; ptr < end; ptr += Size) {
		overridehookdecl h{};
		if (DLL.ReadBytes(ptr, Size, &h)) {
			// msvc linker inserts arbitrary padding between variables that come
			// from different translation units
			if (h.hookNamePtr && h.overrideModuleName) {
				auto const rawNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
				auto const rawModuleNamePtr = DLL.VirtualToRaw(h.overrideModuleName - base);
				if (DLL.ReadCString(rawNamePtr, hookName) && DLL.ReadCString(rawModuleNamePtr,moduleName)) {
					overriderBuffer.add(reinterpret_cast<void*>(h.hookAddr), moduleName, hookName, h.hookSize);
					supposehook.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize);
				}
			}
		}
		else {
			Log::WriteLine(__FUNCTION__ ": Bytes read failed");
			return false;
		}
	}

	return true;
}

// check whether the library wants to be included. if it exports a special
// function, we initiate a handshake. if it fails, or the dll opts out,
// the hooks aren't included. if the function is not exported, we have to
// rely on other methods.
bool SyringeDebugger::Handshake(
	std::string_view lib, int const hooks, unsigned int const crc)
{
	bool ret = false;

	if (!lib.empty()) {
		if (!lib.contains("cncnet")) {
			if (auto const nDllLib = LoadLibrary(lib.data())) {
				if (auto const func = reinterpret_cast<SYRINGEHANDSHAKEFUNC>(
					GetProcAddress(nDllLib, "SyringeHandshake")))
				{
					Log::WriteLine(__FUNCTION__ ": Calling \"%s\" ...", lib.data());
					constexpr auto Size = 0x100u;
					std::vector<char> buffer(Size + 1); // one more than we tell the dll

					auto const shInfo = std::make_unique<SyringeHandshakeInfo>();
					shInfo->cbSize = sizeof(SyringeHandshakeInfo);
					shInfo->num_hooks = hooks;
					shInfo->checksum = crc;
					shInfo->exeFilesize = dwExeSize;
					shInfo->exeTimestamp = dwTimeStamp;
					shInfo->exeCRC = dwExeCRC;
					shInfo->cchMessage = static_cast<int>(Size);
					shInfo->Message = buffer.data();

					if (auto const res = func(shInfo.get()); SUCCEEDED(res)) {
						buffer.back() = 0;
						Log::WriteLine(
							__FUNCTION__ ": Answers \"%s\" (%X)", buffer.data(), res);
						ret = (res == S_OK);
					}
					else {
						// don't use any properties of shInfo.
						Log::WriteLine(__FUNCTION__ ": Failed (%X)", res);
						ret = false;
					}
				}
				else {
					Log::WriteLine(__FUNCTION__ ": Not available.");
				}

				FreeLibrary(nDllLib);
			}
		}
		else {
			SyringeDebugger::IgnoredDlls.push_back(lib.data());
			Log::WriteLine(__FUNCTION__ ": %s Ignored.", lib.data());
		}
	}

	return ret;
}
