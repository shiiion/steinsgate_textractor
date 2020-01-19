#include <string>
#include <iostream>

#include <io.h>
#include <fcntl.h>
#include <Windows.h>

#include "process_utils.h"
#include "sg_text_extractor.h"
#include "mages_string_map.h"

void copy_string_to_clipboard(std::wstring const& str)
{
	if (!OpenClipboard(NULL)) {
		return;
	}
	if (!EmptyClipboard()) {
		CloseClipboard();
		return;
	}
	HGLOBAL clipboard_data = GlobalAlloc(GMEM_MOVEABLE, (str.size() + 1) * sizeof(wchar_t));
	memcpy(GlobalLock(clipboard_data), str.data(), (str.size() + 1) * sizeof(wchar_t));
	GlobalUnlock(clipboard_data);
	SetClipboardData(CF_UNICODETEXT, clipboard_data);
	CloseClipboard();
	GlobalFree(clipboard_data);
}

DWORD choose_process_cli(std::vector<DWORD> const& proc_list) {
	std::wcout << L"WARNING! This will write memory to the target process, so careful what you attach to!" << std::endl;
	if (proc_list.size() == 1) {
		std::wcout << L"Game.exe found with PID=" << proc_list[0] << std::endl;
		std::wcout << L"Attach to this process? (y/n) : ";
		wchar_t resp;
		std::wcin >> resp;
		if (resp == L'y' || resp == L'Y') {
			return proc_list[0];
		}
		else if (resp == L'n' || resp == L'N') {
			exit(0);
		}
		std::wcout << L"Invalid input" << std::endl;
		return 0;
	}
	std::wcout << L"Multiple Game.exe processes found: " << std::endl;
	for (int i = 0; i < proc_list.size(); i++) {
		std::wcout << (i + 1) << L": PID=" << proc_list[i] << std::endl;
	}
	std::wcout << L"Enter a number (1 - " << proc_list.size() << L") to choose a process to attach to, or 0 to exit : " << std::endl;
	int resp;
	try {
		std::wcin >> resp;
	}
	catch (...) {
		std::wcout << L"Invalid input" << std::endl;
		return 0;
	}
	if (!resp) {
		exit(0);
	}
	if (resp <= proc_list.size()) {
		return proc_list[resp - 1];
	}
	std::wcout << L"Invalid input" << std::endl;
	return 0;
}

int main() {
	std::wcout << L"Looking for Steins;Gate or STEINS;GATE 0 process (Game.exe)" << std::endl;
	_setmode(_fileno(stdout), _O_U16TEXT);
	if (!open_process("Game.exe", choose_process_cli)) {
		std::wcout << L"Failed to find/open Game.exe!" << std::endl;
		Sleep(5000); // Gah I
		return 1;
	}

	std::wcout << L"Loading signatures" << std::endl;
	Game game;
	if ((game = initialize_sigs()) == INVALID) {
		std::wcout << "Failed to load signatures" << std::endl;
		Sleep(5000); // Hate these
		return 2;
	}
	std::wcout << L"Signatures loaded" << std::endl << L"Loading mages_charset.bin" << std::endl;

	// Must provide charset, provided one is ripped from CommitteeOfZero's SciAdv.Net repo
	if (!load_utf_16_mapping("mages_charset.bin")) {
		std::wcout << "Failed to open mages_charset.bin" << std::endl;
		Sleep(5000); // Dumb sleeps
		return 3;
	}

	std::wcout << L"Loaded charset, ready.\n" << std::endl;
	
	SGMainText::install_text_hook();
	SGMainText main_text;
	SGEmailText email_text;
	SG0RINEConversation rine_convo;
	SG0RINESendableMessage rine_msg;

	std::vector<SGFormattedText*> source_list;
	source_list.emplace_back(&main_text);
	if (game == SG) {
		source_list.emplace_back(&email_text);
	}
	else {
		source_list.emplace_back(&rine_convo);
		source_list.emplace_back(&rine_msg);
	}

	while (true) {
		for (SGFormattedText* source : source_list) {
			if (source->extract_string()) {
				std::wstring text;
				source->get_formatted_string(text);
				copy_string_to_clipboard(text);
				std::wcout << text << std::endl;
			}
			Sleep(100);
		}
	}
}