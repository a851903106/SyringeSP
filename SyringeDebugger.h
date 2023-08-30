#pragma once
#define WIN32_LEAN_AND_MEAN
//      WIN32_FAT_AND_STUPID

#include "CRC32.h"
#include "PortableExecutable.h"

#include <cstring>
#include <iostream>
#include <map>
#include <optional>
#include <string_view>

#include <windows.h>

static constexpr size_t MaxNameLength = 0x100u;


class SyringeDebugger
{
public:

	using dllptr = void*;
	using eipptr = void*;
	using MemoryHelper = std::vector<BYTE>;

	static std::vector<std::string> IgnoredDll;

	//accumulate all hooks
	// param :
	// const begin of BreakpointInfo
	// const end of BreakpointInfo
	// default init value
	// bynary operation
	struct HooksAccumulateData {
		size_t count;
		size_t numOverriden;
	};

	SyringeDebugger(std::string_view filename)
		: exe(filename)
	{
		RetrieveInfo();
	}

	// debugger
	void Run(std::string_view arguments);
	DWORD HandleException(DEBUG_EVENT const& dbgEvent);

	// breakpoints
	bool SetBP(void* address);
	void RemoveBP(LPVOID address, bool restoreOpcode);

	// memory
	VirtualMemoryHandle AllocMem(void* address, size_t size);
	bool PatchMem(void* address, void const* buffer, DWORD size);
	bool ReadMem(void const* address, void* buffer, DWORD size);

	// syringe
	void FindDLLs();

	template<typename T = int>
	bool startsWithDigit(const std::string& s)
	{
		if (s.empty())
			return false;

		if (std::isdigit(s.front()))
			return true;

		return (((std::is_signed<T>::value
			&& (s.front() == '-')) || (s.front() == '+'))
			&& ((s.size() > 1) && std::isdigit(s[1])));
	}

	template<typename T = int>
	std::optional<T> stonum(const std::string& st)
	{
		const auto s = trim(st);
		bool ok = startsWithDigit<T>(s);

		auto v = T{};

		if (ok) {
			std::istringstream ss(s);
			ss >> v;
			ok = (ss.peek() == EOF);
		}

		return ok ? v : std::optional<T>{};
	}


private:
	void RetrieveInfo();
	void DebugProcess(std::string_view arguments);

	// helper Functions
	static DWORD __fastcall GetRelativeOffset(void const* from, void const* to);

	template<typename T>
	static void ApplyPatch(void* ptr, T&& data) noexcept
	{
		std::memcpy(ptr, &data, sizeof(data));
	}

	template<typename T>
	static void ApplyPatch(void* ptr, T&& data , size_t size) noexcept {
		std::memcpy(ptr, &data, size);
	}
	// thread info
	struct ThreadInfo
	{
		ThreadInfo() = default;

		ThreadInfo(HANDLE hThread) noexcept
			: Thread{hThread}
		{ }

		ThreadHandle Thread;
		LPVOID lastBP{ nullptr };
	};

	std::map<DWORD, ThreadInfo> Threads;

	// process info
	PROCESS_INFORMATION pInfo;

	// flags
	bool bEntryBP{ true };

	// breakpoints
	struct Hook
	{
		unsigned int hookaddr;
		char lib[MaxNameLength]; //module name
		char proc[MaxNameLength]; //hook real name
		void* proc_address;	//hook address

		size_t num_overridden;
	};

#pragma pack(push, 1)
	struct __declspec(novtable)
		DllPatcher {
		uintptr_t offset;
		size_t size;
		BYTE* pData;

		void Apply() {
			void* pAddress = (void*)this->offset;

			DWORD protect_flag;
			VirtualProtect(pAddress, this->size, PAGE_EXECUTE_READWRITE, &protect_flag);
			std::memcpy(pAddress, this->pData, this->size);
			VirtualProtect(pAddress, this->size, protect_flag, 0);
		}
	};
#pragma pack(pop)

	static std::map<std::string, DllPatcher*> PatcherMap;

	void ApplyPatches();

	struct BreakpointInfo
	{
		BYTE original_opcode{ 0x0u };
		std::vector<Hook> hooks;
		VirtualMemoryHandle p_caller_code;
	};

	std::map<eipptr, BreakpointInfo> Breakpoints;

	std::vector<Hook*> v_AllHooks;
	std::vector<Hook*>::iterator loop_LoadLibrary;

	// syringe
	std::string exe;
	void* pcEntryPoint{ nullptr };
	void* pImLoadLibrary{ nullptr };
	void* pImGetProcAddress{ nullptr };
	VirtualMemoryHandle pAlloc;
	DWORD dwTimeStamp{ 0u };
	DWORD dwExeSize{ 0u };
	DWORD dwExeCRC{ 0u };

	bool bDLLsLoaded{ false };
	bool bHooksCreated{ false };

	bool bAVLogged{ false };

	// data addresses
	struct AllocData {
		static constexpr size_t CodeSize = 0x39u;
		std::byte LoadLibraryFunc[CodeSize];
		void* ProcAddress;
		void* ReturnEIP;
		char LibName[MaxNameLength];
		char ProcName[MaxNameLength];
	};

	AllocData* GetData() const noexcept {
		return reinterpret_cast<AllocData*>(pAlloc.get());
	};

	struct HookBuffer {
		std::map<eipptr, std::vector<Hook>> hooks;
		CRC32 checksum;
		size_t count{ 0 };

		void add(eipptr const eip, Hook const& hook) {
			auto& h = hooks[eip];
			h.push_back(hook);

			checksum.compute(&eip, sizeof(eip));
			checksum.compute(&hook.num_overridden, sizeof(hook.num_overridden));
			count++;
		}

		void add(
			eipptr const eip, std::string_view const filename,
			std::string_view const proc, size_t const num_overridden)
		{
			Hook hook;
			hook.lib[filename.copy(hook.lib, std::size(hook.lib) - 1)] = '\0';
			hook.proc[proc.copy(hook.proc, std::size(hook.proc) - 1)] = '\0';
			hook.proc_address = nullptr;
			hook.num_overridden = num_overridden;
			hook.hookaddr = (size_t)eip;

			add(eip, hook);
		}

		void remove(std::string_view const proc, eipptr const eip)
		{
			if (!hooks.contains(eip))
				return;

			auto& nHookv = hooks.at(eip);
			for (size_t i = 0; i < nHookv.size(); ++i) {
				if (proc == nHookv.at(i).proc) {
					nHookv.erase(nHookv.begin() + i);
				}
			}
		}

		size_t GetCurentSize() const
		{ return hooks.size(); }
	};

	bool ParseInjFileHooks(std::string_view lib, HookBuffer& hooks, const char* extension);
	bool CanHostDLL(PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hosts) const;
	bool ParseHooksSection(PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hooks, HookBuffer& buffer);
	bool ParseOverrideHooksSection(PortableExecutable const& DLL, IMAGE_SECTION_HEADER const& hooks, HookBuffer& hookneedtoremove, HookBuffer& bufferAdd);
	bool ParsePatchSection(PortableExecutable const& DLL);

	bool Handshake(std::string_view lib, int hooks, unsigned int crc);
protected :
	void WriteHooks(MemoryHelper& tempmemory, eipptr breakpoints_entry , BreakpointInfo& breakpoins_breaks , const HooksAccumulateData& hooks_, int idx);
	static void __declspec(noinline) RemoveBreakPoints(std::map<void*, BreakpointInfo>& breakpoints, HookBuffer& excludeHooksData);
};

// disable "structures padded due to alignment specifier"
#pragma warning(push)
#pragma warning(disable : 4324)
struct alignas(16) hookdecl {
	unsigned int hookAddr;
	unsigned int hookSize;
	DWORD hookNamePtr;
};

struct alignas(16) overridehookdecl {
	unsigned int hookAddr;
	unsigned int hookSize;
	DWORD hookNamePtr;
	DWORD overrideModuleName;
};

struct alignas(16) hostdecl {
	unsigned int hostChecksum;
	DWORD hostNamePtr;
};

static_assert(sizeof(hookdecl) == 16);
static_assert(sizeof(hostdecl) == 16);
#pragma warning(pop)

struct SyringeHandshakeInfo
{
	int cbSize;
	int num_hooks;
	unsigned int checksum;
	DWORD exeFilesize;
	DWORD exeTimestamp;
	unsigned int exeCRC;
	int cchMessage;
	char* Message;
};

using SYRINGEHANDSHAKEFUNC = HRESULT(__cdecl *)(SyringeHandshakeInfo*);
