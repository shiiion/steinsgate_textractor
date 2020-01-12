#include "process_utils.h"

#include <tuple>
#include <vector>

#include <Psapi.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace {
	HANDLE target_process = NULL;
	DWORD executable_base = 0xFFFFFFFF;
}

bool open_process(std::string const& window_title) {
	DWORD proc_id;
	HWND proc_window = FindWindowA(nullptr, window_title.c_str());
	if (proc_window == NULL) {
		return false;
	}
	GetWindowThreadProcessId(proc_window, &proc_id);
	target_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, proc_id);
	return target_process != NULL;
}

HMODULE get_module(std::string const& target_module_name) {
	DWORD needed;
	HMODULE module_list[1024];
	EnumProcessModules(target_process, module_list, sizeof(module_list) * sizeof(HMODULE), &needed);
	for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
		char module_path[1024];
		GetModuleFileNameExA(target_process, module_list[i], module_path, 1024);
		char* module_name = PathFindFileNameA(module_path);
		if (target_module_name == module_name) {
			return module_list[i];
		}
	}
	return NULL;
}

DWORD get_executable_base() {
	if (executable_base != 0xFFFFFFFF) {
		return executable_base;
	}
	return executable_base = reinterpret_cast<DWORD>(get_module("Game.exe"));
}

HANDLE get_process_handle() {
	return target_process;
}

namespace {
	bool sig_match(std::vector<BYTE> const& pattern, std::vector<BYTE> const& mask, BYTE* data) {
		for (size_t i = 0; i < pattern.size(); i++) {
			if (mask[i]) continue;
			if (pattern[i] != data[i]) return false;
		}
		return true;
	}

	struct SectionInfo {
		DWORD section_base;
		DWORD section_size;
	};

	std::vector<SectionInfo> get_all_code_sections(HMODULE module) {
		MODULEINFO info;
		if (!GetModuleInformation(target_process, module, &info, sizeof(MODULEINFO))) {
			return {};
		}

		std::vector<SectionInfo> ret;
		DWORD pe_walk = reinterpret_cast<DWORD>(module);
		IMAGE_DOS_HEADER dos_hdr;
		ReadProcessMemory(target_process, reinterpret_cast<LPCVOID>(pe_walk), &dos_hdr, sizeof(IMAGE_DOS_HEADER), NULL);
		pe_walk += dos_hdr.e_lfanew;
		IMAGE_NT_HEADERS32 nt_hdrs;
		ReadProcessMemory(target_process, reinterpret_cast<LPCVOID>(pe_walk), &nt_hdrs, sizeof(IMAGE_NT_HEADERS32), NULL);
		pe_walk += sizeof(IMAGE_NT_HEADERS32);
		for (int i = 0; i < nt_hdrs.FileHeader.NumberOfSections; i++) {
			IMAGE_SECTION_HEADER sec_hdr;
			ReadProcessMemory(target_process, reinterpret_cast<LPCVOID>(pe_walk + i * sizeof(IMAGE_SECTION_HEADER)), &sec_hdr, sizeof(IMAGE_SECTION_HEADER), NULL);
			if (sec_hdr.Name[0] == '.' &&
				sec_hdr.Name[1] == 't' &&
				sec_hdr.Name[2] == 'e' &&
				sec_hdr.Name[3] == 'x' &&
				sec_hdr.Name[4] == 't') {
				ret.emplace_back(SectionInfo { (reinterpret_cast<DWORD>(info.lpBaseOfDll) + sec_hdr.VirtualAddress), sec_hdr.Misc.VirtualSize });
			}

		}
		return ret;
	}

	std::pair<std::vector<BYTE>, std::vector<BYTE>> construct_pattern_mask(std::string const& pattern) {
		std::vector<BYTE> bytes, mask;

		// no error handling, heed warning
		auto hex_to_nibble = [](char c) -> BYTE {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			return 0;
		};
		auto hex_to_byte = [&hex_to_nibble](std::string::const_iterator i) -> BYTE {
			return (hex_to_nibble(*i) << 4) | hex_to_nibble(*(i + 1));
		};

		for (size_t i = 0; i < pattern.size(); i += 3) {
			if (pattern[i] == '?') {
				bytes.emplace_back(0);
				mask.emplace_back(1);
			}
			else {
				bytes.emplace_back(hex_to_byte(pattern.begin() + i));
				mask.emplace_back(0);
			}
		}
		return std::make_pair(std::move(bytes), std::move(mask));
	}
}

std::vector<DWORD> external_batch_sigscan(std::string const& module, std::vector<std::string> const& patterns) {
	HMODULE target_module = get_module(module);
	if (target_module == NULL) {
		return {};
	}
	std::vector<DWORD> results;
	results.resize(patterns.size());

	auto sections = get_all_code_sections(target_module);
	for (SectionInfo const& section : sections) {
		std::vector<BYTE> section_data;
		section_data.resize(section.section_size);
		SIZE_T bytes_read;
		ReadProcessMemory(target_process, reinterpret_cast<LPCVOID>(section.section_base), section_data.data(), section_data.size(), &bytes_read);

		for (size_t i = 0; i < patterns.size(); i++) {
			if (results[i]) {
				continue;
			}

			std::vector<BYTE> bytes, mask;
			std::tie(bytes, mask) = construct_pattern_mask(patterns[i]);

			for (DWORD j = 0;
				j < (section.section_size - bytes.size() + 1);
				j++) {
				if (sig_match(bytes, mask, &section_data[j])) {
					results[i] = section.section_base + j;
					break;
				}
			}
		}
	}
	return results;
}