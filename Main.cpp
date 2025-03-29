#include "Log.h"
#include "SyringeDebugger.h"
#include "Support.h"

#include <string>

#include <commctrl.h>
#include <iostream>
#include "ini-rw/include/IniFile.hpp"

int Run(std::string_view const arguments) {
	constexpr auto const VersionString = "Syringe 0.7.3.8";

	InitCommonControls();

	Log::Open("syringe.log");
	inirw::IniFile iniFile("syringeconfig.ini");

	Log::WriteLine(VersionString);
	Log::WriteLine("===============");
	Log::WriteLine();
	//Log::WriteLine("WinMain: arguments = \"%.*s\"", printable(arguments));

	Log::WriteLine(
		"WinMain: try to find syringeconfig");

	if (iniFile) {

		if (inirw::IniKey* iniKey = iniFile.get_key_and_name("General", "IgnorableDlls")) {

			std::string nRes = iniKey->ValueCommentPair.get_value();

			if (!nRes.empty()) {
				char* context = nullptr;
				for (char* cur = strtok_s(nRes.data(), ",", &context);
					cur;
					cur = strtok_s(nullptr, ",", &context))
				{
					SyringeDebugger::IgnoredDll.push_back(cur);
				}
			}
		}

		if(inirw::IniKey* iniKey_HookRemoved = iniFile.get_key_and_name("Logger", "LogHookRemoved")) {
			const std::string nRes = iniKey_HookRemoved->ValueCommentPair.get_value();

			if (!nRes.empty()) {
				inirw::TryParse(nRes.c_str(), &SyringeDebugger::LoggerOptions::LogHookRemove);
			}
		}

		if (inirw::IniKey* iniKey_LoadLib = iniFile.get_key_and_name("Logger", "LogLoadLib")) {
			const  std::string nRes = iniKey_LoadLib->ValueCommentPair.get_value();

			if (!nRes.empty()){
				inirw::TryParse(nRes.c_str(), &SyringeDebugger::LoggerOptions::LogLoadLibFunc);
			}
		}
	}
	else {
		Log::WriteLine(
			"WinMain: could not find syringeconfig.ini ");
	}

	Log::WriteLine(
		"WinMain: find syringeconfig done");

	auto failure = "Could not load executable.";
	auto exit_code = ERROR_ERRORS_ENCOUNTERED;

	try
	{
		auto const command = get_command_line(arguments);

		if (!command.flags.empty()) {
			// artificial limitation
			throw invalid_command_arguments{};
		}

		Log::WriteLine(
			"WinMain: Trying to load executable file \"%.*s\"...",
			printable(command.executable));
		Log::WriteLine();
		auto Debugger = std::make_unique<SyringeDebugger>(command.executable);
		failure = "Could not run executable.";

		Log::WriteLine("WinMain: SyringeDebugger::FindDLLs();");
		Log::WriteLine();
		Debugger->FindDLLs();

		//Log::WriteLine(
		//	"WinMain: SyringeDebugger::Run(\"%.*s\");",
		//	printable(command.arguments));
		Log::WriteLine();

		//MessageBoxA(
		//	nullptr, "Syringe  Halted",
		//	VersionString, MB_OK | MB_ICONINFORMATION);
		Debugger->Run(command.arguments);
		Log::WriteLine("WinMain: SyringeDebugger::Run finished.");
		Log::WriteLine("WinMain: Exiting on success.");
		return ERROR_SUCCESS;
	}
	catch (lasterror const& e)
	{
		auto const message = replace(e.message, "%1", e.insert);
		Log::WriteLine("WinMain: %s (%d)", message.c_str(), e.error);

		auto const msg = std::string(failure) + "\n\n" + message;
		MessageBoxA(nullptr, msg.c_str(), VersionString, MB_OK | MB_ICONERROR);

		exit_code = static_cast<long>(e.error);
	}
	catch (invalid_command_arguments const&)
	{
		MessageBoxA(
			nullptr, "Syringe cannot be run just like that.\n\n"
			"Usage:\nSyringe.exe \"<exe name>\" <arguments>",
			VersionString, MB_OK | MB_ICONINFORMATION);

		Log::WriteLine(
			"WinMain: No or invalid command line arguments given, exiting...");

		exit_code = ERROR_INVALID_PARAMETER;
	}

	Log::WriteLine("WinMain: Exiting on failure.");
	return static_cast<int>(exit_code);
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(nCmdShow);

	//MessageBoxA(
	//	nullptr, "Syringe Is halted before run",
	//	reinterpret_cast<LPCSTR>("TEST"), MB_OK | MB_ICONINFORMATION);

	return Run(lpCmdLine);
}