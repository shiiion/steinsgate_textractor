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

int main() {
	std::wcout << "Looking for Steins;Gate or STEINS;GATE 0 window" << std::endl;
	_setmode(_fileno(stdout), _O_U16TEXT);
	while (!open_process("Steins;Gate") && !open_process("STEINS;GATE 0")) {
		Sleep(500);
	}
	std::wcout << L"Game found" << std::endl << L"Loading signatures" << std::endl;
	Game game;
	if ((game = initialize_sigs()) == INVALID) {
		std::wcout << "Failed to load signatures" << std::endl;
		return 1;
	}
	std::wcout << L"Signatures loaded" << std::endl << L"Loading mages_charset.bin" << std::endl;

	// Must provide charset, provided one is ripped from CommitteeOfZero's SciAdv.Net repo
	if (!load_utf_16_mapping("mages_charset.bin")) {
		std::wcout << "Failed to open mages_charset.bin" << std::endl;
		return 2;
	}

	std::wcout << L"Loaded charset, ready.\n" << std::endl;

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