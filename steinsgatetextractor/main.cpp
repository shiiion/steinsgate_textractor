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
	std::wcout << "Looking for Steins;Gate window" << std::endl;
	_setmode(_fileno(stdout), _O_U16TEXT);
	while (!open_process("Steins;Gate")) {
		Sleep(500);
	}
	std::wcout << L"Steins;Gate process found" << std::endl << L"Loading signatures" << std::endl;
	if (!initialize_sg_sigs()) {
		std::wcout << "Failed to load signatures" << std::endl;
		return 1;
	}
	std::wcout << L"Signatures loaded" << std::endl << L"Loading mages_charset.bin" << std::endl;

	// Must provide charset, provided one is ripped from CommitteeOfZero's SciAdv.Net repo
	if (!load_utf_16_mapping("mages_charset.bin")) {
		std::wcout << "Failed to open mages_charset.bin" << std::endl;
		return 2;
	}

	SGMainText main_text;
	SGEmailText mail_text;
	while (true) {
		if (main_text.extract_string()) {
			std::wstring text;
			main_text.get_formatted_string(text);
			copy_string_to_clipboard(text);
			std::wcout << text << std::endl;
		}
		if (mail_text.extract_string()) {
			std::wstring text;
			mail_text.get_formatted_string(text);
			copy_string_to_clipboard(text);
			std::wcout << text << std::endl;
		}
		Sleep(50);
	}
}