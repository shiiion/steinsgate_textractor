#include "mages_string_map.h"

#include <fstream>
#include <vector>

std::vector<wchar_t> utf_16_mapping;

bool load_utf_16_mapping(std::string const& path) {
	std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		return false;
	}
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	utf_16_mapping.resize((size + 1) / 2);
	file.read(reinterpret_cast<char*>(&utf_16_mapping[0]), size);
	return true;
}

wchar_t lookup_mages_codepoint(uint16_t code_point) {
	if (code_point > utf_16_mapping.size()) {
		return 0;
	}
	return utf_16_mapping[code_point];
}