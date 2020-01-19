#pragma once

#include <string>
#include <vector>

#include <Windows.h>

#include "jmp_hook.h"

enum Game {
	SG,
	SG0,
	INVALID,
};

// returns successful initialize
Game initialize_sigs();

struct SyllabizedWord {
	SyllabizedWord(size_t insert_point) : insert_point(insert_point) {}

	std::wstring ruby;
	std::wstring word;
	size_t insert_point;
	bool operator==(SyllabizedWord const& other) const {
		return ruby == other.ruby &&
			word == other.word &&
			insert_point == other.insert_point;
	}
};

class SGFormattedText {
public:
	virtual bool extract_string() = 0;
	virtual void get_formatted_string(std::wstring& str_out) const = 0;
};

class SGEmailText : public SGFormattedText {
public:
	static DWORD get_phone_state();

	bool extract_string() override;
	void get_formatted_string(std::wstring& str_out) const override;

private:
	constexpr static DWORD PHONE_STATE_SENT = 4;
	constexpr static DWORD PHONE_STATE_RCVD = 5;
	constexpr static DWORD PHONE_STATE_SENDABLE = 22;
	constexpr static DWORD PHONE_STATE_RCVD_RESPONDABLE = 27;
	
	std::wstring contact;
	std::wstring subject;
	std::wstring body;
	DWORD phone_state;
};

class SG0RINEMessage : public SGFormattedText {
public:
	constexpr static DWORD PHONE_STATE_RINE = 7;
	constexpr static DWORD PHONE_STATE_RINE_RESPOND = 8;

	static DWORD get_phone_state();

	bool extract_string() override;
	void get_formatted_string(std::wstring& str_out) const override;
	int get_message_count() const;

protected:
	std::wstring sender_name;
	std::wstring message;
	int last_message_index = 0;
};

class SG0RINEConversation : public SG0RINEMessage {
public:
	bool extract_string() override;
	void get_formatted_string(std::wstring& str_out) const override;

private:
	std::vector<std::wstring> all_senders;
	std::vector<std::wstring> all_messages;
	mutable int last_copy_index;
};

class SG0RINESendableMessage : public SGFormattedText {
public:
	bool extract_string() override;
	void get_formatted_string(std::wstring& str_out) const override;

private:
	std::wstring sendable_message;
};

class SGMainText : public SGFormattedText {
public:
	static void install_text_hook();

	bool extract_string() override;
	void get_formatted_string(std::wstring& str_out) const override;

	constexpr bool ruby_enabled() const { return _ruby_enabled; }
	constexpr void enable_ruby() { _ruby_enabled = true; }
	constexpr void disable_ruby() { _ruby_enabled = false; }

private:
	bool _ruby_enabled = true;

	static JmpHook extract_hook;
	static DWORD text_ptr_page;

	std::wstring speaker;
	std::vector<SyllabizedWord> syllabized_words;
	std::wstring unformatted_text;
};