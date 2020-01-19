#include "jmp_hook.h"

#include "process_utils.h"

std::pair<uint32_t, uint32_t> JmpHook::rwx_page = {};

void JmpHook::fill_dword(uint32_t val, int offset) {
	*reinterpret_cast<uint32_t*>(hook.data() + offset) = val;
}

void JmpHook::fill_jmp(uint32_t target, int offset) {
	if (!rwx_page.first || (rwx_page.second + hook.size() > 0x1000)) {
		rwx_page = std::make_pair(allocate_page(), 0);
	}
	uint32_t source = static_cast<uint32_t>(offset) + rwx_page.first + rwx_page.second;
	// instruction starts 1 byte before
	fill_dword(target - source - 4, offset);
}

void JmpHook::insert_hook(uint32_t address, uint32_t overwrite_len) {
	if (!rwx_page.first || (rwx_page.second + hook.size() > 0x1000)) {
		rwx_page = std::make_pair(allocate_page(), 0);
	}
	DWORD hook_addr = rwx_page.first + rwx_page.second;
	WriteProcessMemory(get_process_handle(), reinterpret_cast<LPVOID>(hook_addr), hook.data(), hook.size(), NULL);
	rwx_page.second += hook.size();
	uint8_t jmp_instruction[5] = { 0xE9 };
	uint8_t nop_instruction = 0x90;
	*reinterpret_cast<uint32_t*>(jmp_instruction + 1) = (hook_addr - address - 5);
	WriteProcessMemory(get_process_handle(), reinterpret_cast<LPVOID>(address), jmp_instruction, 5, NULL);
	for (uint32_t i = 5; i < overwrite_len; i++) {
		WriteProcessMemory(get_process_handle(), reinterpret_cast<LPVOID>(address + i), &nop_instruction, 1, NULL);
	}
}