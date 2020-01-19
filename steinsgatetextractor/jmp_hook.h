#pragma once

#include <string>
#include <vector>
#include <stdint.h>

// Simple hook class, make sure hooks < page size
// No return jmp added, does not save regs, stack, original instruction
class JmpHook {
private:
	std::vector<uint8_t> hook;
	// leak it, who cares
	static std::pair<uint32_t, uint32_t> rwx_page;
public:
	JmpHook(std::vector<uint8_t>&& hook) : hook(std::move(hook)) {}

	void fill_dword(uint32_t val, int offset);
	void fill_jmp(uint32_t target, int offset);
	// No instruction decoder
	void insert_hook(uint32_t address, uint32_t overwrite_len);
};