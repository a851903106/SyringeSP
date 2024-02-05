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

//using namespace std;
std::vector<std::string> SyringeDebugger::IgnoredDll;
std::map<std::string, SyringeDebugger::DllPatcher*> SyringeDebugger::PatcherMap;

#pragma pack(push, 1)
// 8-bit relative jump.
typedef struct _JMP_REL_SHORT {
	UINT8  opcode;      // EB xx: JMP +2+xx
	UINT8  operand;

	static constexpr inline size_t size() {
		return sizeof(_JMP_REL_SHORT);
	}

} JMP_REL_SHORT, * PJMP_REL_SHORT;

// 32-bit direct relative jump/call.
typedef struct _JMP_REL {
	UINT8  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
	UINT32 operand;     // Relative destination address

	static constexpr inline size_t size() {
		return sizeof(_JMP_REL);
	}

} JMP_REL, * PJMP_REL, CALL_REL;

// 32-bit direct relative conditional jumps.
typedef struct _JCC_REL {
	UINT8  opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
	UINT8  opcode1;
	UINT32 operand;     // Relative destination address

	static constexpr inline size_t size() {
		return sizeof(_JCC_REL);
	}

} JCC_REL;

#pragma pack(pop)

struct Assembly {

	static constexpr BYTE INIT = 0x00 ,
	INT3 = 0xCC ,
	NOP = 0x90 ,
	CALL = 0xE8 ,
	JMP = 0xE9 ,
	JLE = 0x7E;

	static constexpr BYTE const this2fastcall[] = {
			0x8B, 0x54, 0xE4, 0x08, //MOV EDX, [ESP + 8]
			0x58, // POP EAX
			0x89, 0x44, 0xE4, 0x04, // MOV [ESP + 4], EAX
			0x89, 0xC8, // MOV EAX, ECX
			0x59, // POP ECX
			0xFF, 0xE0 // JMP EAX
	};
	static constexpr auto sizeof_this2fastcall = sizeof(this2fastcall);

	static constexpr BYTE const jmp_code_[] = {
			0x58, // POP EAX
			0x83, 0xC4, 0x04, // ADD ESP, 4
			0xFF, 0xE0 // JMP EAX
	};
	static constexpr size_t sizeof_jmp_code_ = sizeof(jmp_code_);


	static constexpr BYTE const load_library[] = {
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
	static constexpr size_t sizeof_load_library = sizeof(load_library);

	//constexpr static BYTE const hook_code_call_old[] = {
	//	0x60, 0x9C, // PUSHAD, PUSHFD
	//	0x68, INIT, INIT, INIT, INIT, // PUSH HookAddress
	//	0x54, // PUSH ESP
	//	0xE8, INIT, INIT, INIT, INIT, // CALL ProcAddress
	//	0x83, 0xC4, 0x08, // ADD ESP, 8
	//	0xA3, INIT, INIT, INIT, INIT, // MOV ds:JmpBack, EAX
	//	0x9D, 0x61, // POPFD, POPAD
	//	0x83, 0x3D, INIT, INIT, INIT, INIT, 0x00, // CMP ds:JmpBack, 0
	//	0x74, 0x06, // JZ .proceed
	//	0xFF, 0x25, INIT, INIT, INIT, INIT, // JMP ds:JmpBack
	//};
	//static constexpr size_t sizeof_hook_code_call_old = sizeof(hook_code_call_old);

	constexpr static BYTE const hook_code_call[] = {
		0x60, 0x9C, // PUSHAD, PUSHFD
		0x68, INIT, INIT, INIT, INIT, // PUSH HookAddress
		0x54, // PUSH ESP
		CALL, INIT, INIT, INIT, INIT, // insert E8 (CALL) ProcAddress
		0x83, 0xC4, 0x08, // ADD ESP, 8
		0x89, 0x44, 0x24, 0xFC,// MOV ds:JmpBack, EAX
		0x9D, 0x61, // POPFD, POPAD
		0x83, 0x7C, 0x24, 0xD8, INIT, 0x74,// CMP ds:JmpBack, 0
		0x04, 0xFF, // JZ .proceed
		0x64, 0x24, 0xD8 , INIT , INIT , INIT// JMP ds:JmpBack
	};
	static constexpr size_t sizeof_hook_code_call = sizeof(hook_code_call);
	static_assert(sizeof_hook_code_call == 36u, "Invalid Size!");


	//constexpr static BYTE const hoke_code_call_DP[] = {
	//	0x60, 0x9C, //PUSHAD, PUSHFD
	//	0x68, INIT, INIT, INIT, INIT, //PUSH HookAddress
	//	0x83, 0xEC, 0x04,//SUB ESP, 4
	//	0x8D, 0x44, 0x24, 0x04,//LEA EAX,[ESP + 4]
	//	0x50, //PUSH EAX
	//	0xE8, INIT, INIT, INIT, INIT,  //CALL ProcAddress
	//	0x83, 0xC4, 0x0C, //ADD ESP, 0Ch
	//	0x89, 0x44, 0x24, 0xF8,//MOV ss:[ESP - 8], EAX
	//	0x9D, 0x61, //POPFD, POPAD
	//	0x83, 0x7C, 0x24, 0xD4, 0x00,//CMP ss:[ESP - 2Ch], 0
	//	0x74, 0x04, //JZ .proceed
	//	0xFF, 0x64, 0x24, 0xD4 //JMP ss:[ESP - 2Ch]
	//};
	//static constexpr size_t sizeof_hoke_code_call_DP = sizeof(hoke_code_call_DP);


	//constexpr static BYTE const jmp[] = { 0xE9, INIT, INIT, INIT, INIT };
	//static constexpr size_t sizeof_jmp = sizeof(jmp);

	//constexpr static BYTE const call[] = { 0xE8, INIT, INIT, INIT, INIT };
	//static constexpr size_t sizeof_call = sizeof(call);

	struct JumpStruct {
		uintptr_t From;
		uintptr_t To;

		uintptr_t getOffset() const {
			return To - From - JMP_REL::size();
		}
	};

	//template<typename T>
	//static bool ReadFromAddr(uintptr_t address, T& obj) {
	//	BYTE mem[sizeof(T)];
	//	bool ret = SyringeDebugger::ReadMem((void*)address, mem, sizeof(T));
	//	std::memcpy(obj, mem, sizeof(T));
	//	return ret;
	//}

};

void SyringeDebugger::ApplyPatches() {}

//TODO : Other Type of hook supports !

/*
*	Apply patch:
*	Type -> raw
*		 -> address
*/
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

bool SyringeDebugger::ReadMem(void const* address, void* destinationbuffer, DWORD size)
{
	return (ReadProcessMemory(pInfo.hProcess, address, destinationbuffer, size, nullptr) != FALSE);
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
		auto const buffer = Assembly::INT3;
		ReadMem(address, &opcode, 1);
		return PatchMem(address, &buffer, 1);
	}

	return true;
}

DWORD __fastcall SyringeDebugger::GetRelativeOffset(void const* pFrom, void const* pTo)
{
	auto const from = reinterpret_cast<DWORD>(pFrom);
	auto const to = reinterpret_cast<DWORD>(pTo);

	return to - from;
}

//void __declspec(noinline) SyringeDebugger::WriteHooks(MemoryHelper& tempmemory, eipptr breakpoints_entry, BreakpointInfo& breakpoins_breaks, const HooksAccumulateData& hooks_, int idx) {
//
//
//}

DWORD SyringeDebugger::HandleException(DEBUG_EVENT const& dbgEvent)
{
	auto const exceptCode = dbgEvent.u.Exception.ExceptionRecord.ExceptionCode;
	auto const exceptAddr = dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress;

	switch (exceptCode)
	{
	case EXCEPTION_BREAKPOINT:
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
			auto const buffer = Assembly::INT3;
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

				if (!hook->proc_address)
				{
					Log::WriteLine(
						__FUNCTION__ ": Could not retrieve ProcAddress for: %s "
						"- %s", hook->lib, hook->proc);
				}
				else
				{
					Log::WriteLine(__FUNCTION__ ": %s [0x%x , %s , %d]" , hook->lib , hook->hookaddr , hook->proc , hook->num_overridden);
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

				//temporary vector for code Byte
				MemoryHelper tempmemory {};
				MemoryHelper overridenMem {};

				for (auto& [breakpoints_entry, breakpoins_breaks] : Breakpoints)
				{
					tempmemory.clear();
					overridenMem.clear();

					if (breakpoints_entry == nullptr || breakpoints_entry == pcEntryPoint)
					{
						continue;
					}

					// count = how much hook is present
					// overridden = number of overriden of the hook
					HooksAccumulateData hooks_ { 0u , 0u };

					for (const auto& hook : breakpoins_breaks.hooks) {
						if (hook.proc_address && ((uintptr_t)hook.proc_address) != 0x0) {
							if (hooks_.numOverriden < hook.num_overridden) {
								hooks_.numOverriden = hook.num_overridden;
							}

							hooks_.count++;
						}
					}

					if (hooks_.count <= 0)
					{
						continue;
					}

					//Formulate the hook function
					//calculate final sizes
					const auto totalHookSize = hooks_.count * Assembly::sizeof_hook_code_call;
					const auto sz = totalHookSize + JMP_REL::size() + hooks_.numOverriden;

					tempmemory.resize(sz);

					BYTE* memoryptr = tempmemory.data();

					// hook address to be called
					breakpoins_breaks.p_caller_code = AllocMem(nullptr, sz);
					bool checked = false;
					bool needProtect = false;

					//MessageBoxA(
					//	nullptr, "Syringe Is halted before run",
					//	reinterpret_cast<LPCSTR>("TEST"), MB_OK | MB_ICONINFORMATION);

					for (size_t i = 0; i < hooks_.count; ++i)
					{
						const auto& hook = breakpoins_breaks.hooks[i];

						if (hook.proc_address)
						{
							if (!checked && hook.num_overridden > 0)
							{
								//read the overriden bytes
								overridenMem.resize(hook.num_overridden);
								ReadMem(breakpoints_entry, overridenMem.data(), hooks_.numOverriden);

								//found jump or call opcode
								if (overridenMem[0] == Assembly::CALL || overridenMem[0] == Assembly::JMP || overridenMem[0] == Assembly::JLE)
								{
									Log::WriteLine(
										__FUNCTION__ ":Hook at [0x%x = %s , %d] Possibly destroying jmp or call", breakpoints_entry, hook.proc, hook.num_overridden);

									needProtect = true;
								}

								checked = true;
							}

							// write hook caller code
							ApplyPatch(memoryptr, Assembly::hook_code_call, 33u); // code
							//replace the code that needed
							ApplyPatch(memoryptr + 0x03, breakpoints_entry); // PUSH HookAddress
							const auto hook_call_rel = GetRelativeOffset(
								breakpoins_breaks.p_caller_code.get() + (memoryptr - tempmemory.data() + 0x0D)
								, hook.proc_address
							);

							//MessageBoxA(
							//	nullptr, "Syringe Is halted before run",
							//	reinterpret_cast<LPCSTR>("TEST"), MB_OK | MB_ICONINFORMATION);

							CALL_REL relative_call { Assembly::CALL , hook_call_rel };
							//on the original syringe source this was 0x09 
							// replaced to 0x08 since the operand from CALL_REL will be copied too
							ApplyPatch(memoryptr + 0x08, relative_call);
							memoryptr += 0x21; //advance the iterator

						}
					}

					// write overridden bytes to the end
					// this for return 0 case ,..
					if (!overridenMem.empty()) {
						PatchMem(static_cast<BYTE*>(breakpoints_entry), memoryptr, tempmemory.size());
						memoryptr += overridenMem.size();
					}


					// write the jump back for return
					const auto jmp_back_rel = GetRelativeOffset(
						breakpoins_breaks.p_caller_code.get() + (memoryptr - tempmemory.data() + JMP_REL::size()),
						static_cast<BYTE*>(breakpoints_entry) + std::max(hooks_.numOverriden, JMP_REL::size()));

					JMP_REL jmp_back { Assembly::JMP ,  jmp_back_rel };
					ApplyPatch(memoryptr, jmp_back);
					//ApplyPatch(memoryptr + 0x01, jmp_back_rel);

					//write finished hook data to reserved memory
					PatchMem(breakpoins_breaks.p_caller_code.get(), tempmemory.data(), tempmemory.size());

					// replace the original instruction with hook call

					tempmemory.resize(std::max(hooks_.numOverriden, JMP_REL::size()) , Assembly::NOP);

					const auto p_original_code = static_cast<BYTE*>(breakpoints_entry);
					const auto originalcode_rel = GetRelativeOffset(p_original_code + JMP_REL::size(), breakpoins_breaks.p_caller_code.get());
					//resize the temp memory then fill it with NOP
					//apply the jump opcode
					JMP_REL hookjmpOpcode { Assembly::JMP ,  originalcode_rel };
					ApplyPatch(tempmemory.data(), hookjmpOpcode);
					//insert the jump back address
					//ApplyPatch(tempmemory.data() + 0x01, originalcode_rel);
					//patch the memory to the destination
					PatchMem(p_original_code, tempmemory.data(), tempmemory.size());
				}

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
	case EXCEPTION_SINGLE_STEP:
	{
		auto const buffer = Assembly::INT3;
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
	default:
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
			for (auto p = esp; p < &esp[0x100]; ++p)
			{
				DWORD dw;
				if (ReadMem(p, &dw, 4))
				{
					Log::WriteLine("\t0x%08X:\t0x%08X", p, dw);
				}
				else
				{
					Log::WriteLine("\t0x%08X:\t(could not be read)", p);
				}
			}
			Log::WriteLine();

			bAVLogged = true;
		}

		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_CONTINUE;
}

void SyringeDebugger::Run(std::string_view const arguments)
{
	constexpr auto AllocDataSize = sizeof(AllocData);

	static_assert(AllocDataSize == 580u, "InvalidAllocSize");
	Log::WriteLine(
		__FUNCTION__ ": Running process to debug. cmd = \"%s %.*s\"",
		exe.c_str(), printable(arguments));
	DebugProcess(arguments);

	Log::WriteLine(__FUNCTION__ ": Allocating 0x%u bytes...", AllocDataSize);
	pAlloc = AllocMem(nullptr, AllocDataSize);

	Log::WriteLine(__FUNCTION__ ": pAlloc = 0x%08X", pAlloc.get());

	// write DLL loader code
	Log::WriteLine(__FUNCTION__ ": Writing DLL loader & caller code...");


	std::array<BYTE, AllocDataSize> data;
	static_assert(AllocData::CodeSize >= Assembly::sizeof_load_library, "Invalid Size !");
	ApplyPatch(data.data(), Assembly::load_library);
	ApplyPatch(data.data() + 0x04, &GetData()->LibName);
	ApplyPatch(data.data() + 0x0A, pImLoadLibrary);
	ApplyPatch(data.data() + 0x13, &GetData()->ProcName);
	ApplyPatch(data.data() + 0x1A, pImGetProcAddress);
	ApplyPatch(data.data() + 0x1F, &GetData()->ProcAddress);
	constexpr size_t datasize = data.size();

	if(!PatchMem(pAlloc, data.data(), datasize)){
		Log::WriteLine(__FUNCTION__ ": LoadLibrary patching failed !");
		return;
	}

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
			if(PatchMem(address, &i->second.original_opcode, 1))
				Log::WriteLine("Syringe Attempt to Remove[%X] Break points", address);
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
	if (std::ifstream is{ exe, std::ifstream::binary })
	{
		is.seekg(0, std::ifstream::end);
		dwExeSize = static_cast<DWORD>(is.tellg());
		is.seekg(0, std::ifstream::beg);

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

#include <sstream>

std::string convert_int(int n)
{
	std::stringstream ss;
	ss << n;
	return ss.str();
}

void SyringeDebugger::FindDLLs()
{
	Breakpoints.clear();
	HookOverrideBuffer buffer_remove;

	for (auto file = FindFile("*.dll"); file; ++file) {
		std::string_view const fn(file->cFileName);

		if (!IgnoredDll.empty()) {
			const auto Iter = std::find_if(IgnoredDll.begin(), IgnoredDll.end(), [&](const auto& nStr) { return nStr == fn; });
			if (Iter != IgnoredDll.end()) {
				Log::WriteLine(__FUNCTION__ ": Ignoring DLL: \"%.*s\"", printable(fn));
				continue;
			}
		}
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

				if (auto const hooks = DLL.FindSection(".syhks01")) {
					if (ParseOverrideHooksSection(DLL, *hooks, buffer_remove, buffer))
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
				for (auto const&[eip , hooks] : buffer.hooks) {
					auto& h = Breakpoints[eip];
					h.p_caller_code.clear();
					h.original_opcode = 0x00;
					h.hooks.insert(h.hooks.end(), hooks.begin(), hooks.end());
				}
			}
			else if (!buffer.hooks.empty()) {
				Log::WriteLine(
					__FUNCTION__ ": DLL load was prevented: \"%.*s\"",
					printable(fn));
			}
		}
		catch (...) {
			Log::WriteLine(
				__FUNCTION__ ": DLL Parse failed: \"%.*s\"", printable(fn));
		}
	}

	// summarize all hooks
	v_AllHooks.clear();
	SyringeDebugger::RemoveBreakPoints(Breakpoints, buffer_remove);
	for (auto& it : Breakpoints) {
		for (auto& data : it.second.hooks) {

			auto const nTempData = convert_int(data.hookaddr);

			if ((nTempData.size() + 1) != 8){
				Log::WriteLine(__FUNCTION__ ": Found Hook with less or more than 8 characters , it maybe invalid one [%s][0x%x , %s , %d].", data.lib, data.hookaddr, data.proc, data.num_overridden);
			}

			if(data.num_overridden == 0)
				Log::WriteLine(__FUNCTION__ ": Found Hook with 0 num overriden , it maybe better to explicitly put the correct num overriden [%s][0x%x , %s , %d].", data.lib, data.hookaddr, data.proc, data.num_overridden);
			else if (data.num_overridden < 5)
				Log::WriteLine(__FUNCTION__ ": Found Hook with less than 5 bytes num overriden , it maybe better to move the hook location if possible [%s][0x%x , %s , %d].", data.lib, data.hookaddr, data.proc, data.num_overridden);
			else if (data.num_overridden > 10)
				Log::WriteLine(__FUNCTION__ ": Found Hook with num overriden more than 10 [%s][0x%x , %s , %d].", data.lib, data.hookaddr, data.proc, data.num_overridden);

			v_AllHooks.push_back(&data);
		}

		if (it.second.hooks.size() > 1)
			Log::WriteLine(__FUNCTION__ ":[0x%x , %s , %d] Is Hooked by %d function !.", it.second.hooks[0].hookaddr , it.second.hooks[0].proc , it.second.hooks[0].num_overridden , it.second.hooks.size());

	}

	Log::WriteLine(__FUNCTION__ ": Done (%d hooks added).", v_AllHooks.size());
	Log::WriteLine();
}

void SyringeDebugger::RemoveBreakPoints(std::map<eipptr, BreakpointInfo>& breakpoints, HookOverrideBuffer& excludeHooksData)
{
	if (excludeHooksData.GetCurentSize() <= 0)
		return;

	for (auto& breaks : breakpoints)
	{
		if (breaks.first == nullptr || breaks.second.hooks.empty())
			continue;

		auto Iter = std::remove_if(std::begin(breaks.second.hooks), std::end(breaks.second.hooks), [&excludeHooksData](const SyringeDebugger::Hook& data) {
			
			for (const auto& nVec : excludeHooksData.hooks) {
				if ((_strcmpi(data.lib, nVec.lib) == 0) && //same dll
					data.hookaddr == nVec.hookaddr// same address
					//&& (_strcmpi(nBreakHook.proc , nVec.proc) == 0)
					//&& nBreakHook.num_overridden == i->num_overridden
					)
				{

					Log::WriteLine(__FUNCTION__ ": Removing %s [0x%x , %s , %d] hook.", data.lib, data.hookaddr, data.proc, data.num_overridden);
					return true;
				}
			}

			return false;
		});

		breaks.second.hooks.erase(Iter , std::end(breaks.second.hooks));
	}
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
	hookName.reserve(0x100);

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
	HookOverrideBuffer& hookneedtoremove , HookBuffer& bufferAdd)
{
	constexpr auto const Size = sizeof(hookdecl);
	auto const base = DLL.GetImageBase();
	auto const filename = std::string_view(DLL.GetFilename());

	auto const begin = hooks.PointerToRawData;
	auto const end = begin + hooks.SizeOfRawData;

	std::string hookName{};
	hookName.reserve(0x100);

	std::string moduleName{};
	moduleName.reserve(0x100);

	for (auto ptr = begin; ptr < end; ptr += Size) {
		overridehookdecl h{};
		if (DLL.ReadBytes(ptr, Size, &h)) {
			// msvc linker inserts arbitrary padding between variables that come
			// from different translation units
			if (h.hookNamePtr && h.overrideModuleName) {
				auto const rawhookNamePtr = DLL.VirtualToRaw(h.hookNamePtr - base);
				auto const rawmoduleNamePtr = DLL.VirtualToRaw(h.overrideModuleName - base);
				if (DLL.ReadCString(rawhookNamePtr, hookName) && DLL.ReadCString(rawmoduleNamePtr,moduleName)) {
					hookneedtoremove.add(h.hookAddr, moduleName, hookName, h.hookSize);

					if(h.hookSize != -1)
						bufferAdd.add(reinterpret_cast<void*>(h.hookAddr), filename, hookName, h.hookSize);
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

int GetSection(PortableExecutable const& DLL, const char* sectionName, void** pVirtualAddress) {
	const auto& [addr, size] = DLL.GetSection(sectionName);
	*pVirtualAddress = addr;
	return size;
}

bool SyringeDebugger::ParsePatchSection(
	PortableExecutable const& DLL) {
	auto const filename = DLL.GetFilename();

	void* ptrbuffer;
	const int len = GetSection(DLL ,".patch", &ptrbuffer);
	if (!len)
		return false;

	for (int offset = 0; offset < len; offset += sizeof(DllPatcher))
	{
		const auto pPatch = (DllPatcher*)((DWORD)ptrbuffer + offset);
		if (pPatch->offset == 0)
			continue;

		Log::WriteLine(
			__FUNCTION__ ": Found .patch Section :[%s - %d] [0x%x]", filename , offset, pPatch->offset);

		SyringeDebugger::PatcherMap[filename] = pPatch;
	}

	return true;
}

// check whether the library wants to be included. if it exports a special
// function, we initiate a handshake. if it fails, or the dll opts out,
// the hooks aren't included. if the function is not exported, we have to
// rely on other methods.
bool SyringeDebugger::Handshake(
	std::string_view lib, int const hooks, unsigned int const crc) const
{
	bool ret = false;

	if (!lib.empty()) {
		//if (!lib.contains("cncnet"))
		{
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
		//else {
		//	SyringeDebugger::IgnoredDlls.push_back(lib.data());
		//	Log::WriteLine(__FUNCTION__ ": %s Ignored.", lib.data());
		//}
	}

	return ret;
}
