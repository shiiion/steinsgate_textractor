#include <string>
#include <iostream>

#include <io.h>
#include <fcntl.h>
#include <Windows.h>

#include "process_utils.h"
#include "sg_text_extractor.h"
#include "mages_string_map.h"

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
			std::wcout << text << std::endl;
		}
		if (mail_text.extract_string()) {
			std::wstring text;
			mail_text.get_formatted_string(text);
			std::wcout << text << std::endl;
		}
		Sleep(50);
	}
}