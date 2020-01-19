#pragma once

#include <functional>
#include <string>
#include <vector>

#include <Windows.h>

bool open_process(std::string const& image_name,
	std::function<int(std::vector<DWORD> const&)> on_processes_found);
DWORD get_executable_base();
HANDLE get_process_handle();
DWORD allocate_page();
// Signatures are of form
// <sig>  ::= <byte> <sig> | <byte>
// <byte> ::= <hex><hex> | ??
// <hex>  ::= 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | 
//            b | c | d | e | f | A | B | C | D | E | F
// Deviations cause undefined behavior
std::vector<DWORD> external_batch_sigscan(std::string const& module,
	std::string const& section, std::vector<std::string> const& patterns);