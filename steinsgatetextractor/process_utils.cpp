#include "process_utils.h"

#include <tuple>
#include <vector>

#include <Psapi.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

namespace {
	HANDLE target_process = NULL;
	DWORD executable_base = 0xFFFFFFFF;
}

std::vector<DWORD> find_processes(std::string const& image_name) {
	HANDLE proc_snap;
	if ((proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
		return {};
	}
	
	PROCESSENTRY32 pe_32;
	std::vector<DWORD> ret;
	pe_32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(proc_snap, &pe_32)) {
		do {
			if (image_name == pe_32.szExeFile) {
				ret.emplace_back(pe_32.th32ProcessID);
			}
		} while (Process32Next(proc_snap, &pe_32));
	}
	CloseHandle(proc_snap);
	return ret;
}

bool open_process(std::string const& image_name,
	std::function<int(std::vector<DWORD> const&)> on_processes_found) {
	auto processes_by_image = find_processes(image_name);
	if (!processes_by_image.size()) {
		return false;
	}

	DWORD target_process_id = on_processes_found(processes_by_image);
	if (!target_process_id) {
		return false;
	}

	target_process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, target_process_id);
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

DWORD allocate_page() {
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	DWORD page = reinterpret_cast<DWORD>(VirtualAllocEx(target_process, NULL, info.dwPageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	return page;
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

	SectionInfo get_section_by_name(HMODULE module, std::string const& section_name) {
		MODULEINFO info;
		if (!GetModuleInformation(target_process, module, &info, sizeof(MODULEINFO))) {
			return { 0, 0 };
		}

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
			if (section_name == reinterpret_cast<char const*>(sec_hdr.Name)) {
				return { (reinterpret_cast<DWORD>(info.lpBaseOfDll) + sec_hdr.VirtualAddress), sec_hdr.Misc.VirtualSize };
			}
		}
		return { 0, 0 };
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

std::vector<DWORD> external_batch_sigscan(std::string const& module, std::string const& section, std::vector<std::string> const& patterns) {
	HMODULE target_module = get_module(module);
	if (target_module == NULL) {
		return {};
	}
	std::vector<DWORD> results;
	results.resize(patterns.size());

	auto section_info = get_section_by_name(target_module, section);
	std::vector<BYTE> section_data;
	section_data.resize(section_info.section_size);
	SIZE_T bytes_read;
	ReadProcessMemory(target_process, reinterpret_cast<LPCVOID>(section_info.section_base), section_data.data(), section_data.size(), &bytes_read);

	for (size_t i = 0; i < patterns.size(); i++) {
		if (results[i]) {
			continue;
		}

		std::vector<BYTE> bytes, mask;
		std::tie(bytes, mask) = construct_pattern_mask(patterns[i]);

		for (DWORD j = 0;
			j < (section_info.section_size - bytes.size() + 1);
			j++) {
			if (sig_match(bytes, mask, &section_data[j])) {
				results[i] = section_info.section_base + j;
				break;
			}
		}
	}
	return results;
}