#pragma once

#include <string>

bool load_utf_16_mapping(std::string const& path);
wchar_t lookup_mages_codepoint(uint16_t code_point);