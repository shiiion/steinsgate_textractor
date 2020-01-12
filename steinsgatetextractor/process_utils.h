#pragma once

#include <string>
#include <vector>

#include <Windows.h>

bool open_process(std::string const& window_title);
DWORD get_executable_base();
HANDLE get_process_handle();
// Signatures are of form
// <sig>  ::= <byte> <sig> | <byte>
// <byte> ::= <hex><hex> | ??
// <hex>  ::= 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | a | 
//            b | c | d | e | f | A | B | C | D | E | F
// Deviations cause undefined behavior
std::vector<DWORD> external_batch_sigscan(std::string const& module, std::vector<std::string> const& patterns);