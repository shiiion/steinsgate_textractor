#include "sg_text_extractor.h"

#include <sstream>

#include "process_utils.h"
#include "mages_string_map.h"

namespace {
	DWORD phone_data_ptr = 0;
	DWORD unk1_counter_ptr = 0;
	DWORD unk2_email_data_ptr = 0;
	DWORD unk3_find_email_ptr = 0;
	DWORD markup_buffer_ptr = 0;
	DWORD markup_len_ptr = 0;

	template<typename T>
	T read_single(DWORD base) {
		SIZE_T t_size;
		T t_out;
		ReadProcessMemory(get_process_handle(), reinterpret_cast<LPCVOID>(base), &t_out, sizeof(T), &t_size);
		return t_out;
	}

	void extract_mages_enc_string(DWORD string_start, std::wstring& out_string) {
		std::wostringstream str_builder;
		BYTE token_val = read_single<BYTE>(string_start);
		DWORD cur_index = string_start;
		while (token_val != 0xFF) {
			if (token_val & 0x80) {
				str_builder << lookup_mages_codepoint(((token_val & 0x7F) << 8) | read_single<BYTE>(cur_index + 1));
				cur_index += 2;
			}
			else {
				cur_index++;
			}
			// Add handler for control codes?
			token_val = read_single<BYTE>(cur_index);
		}
		out_string = std::move(str_builder.str());
	}

	// Stolen from IDA decomp, this fn is an absolute mess
	DWORD find_email_text(DWORD unk1, DWORD unk2) {
		const DWORD v2 = read_single<DWORD>(unk3_find_email_ptr + (unk1 * 4));
		const DWORD v3 = unk2 + ((read_single<BYTE>(v2 + 5) + ((read_single<BYTE>(v2 + 6) + (read_single<BYTE>(v2 + 7) << 8)) << 8)) << 6);
		const DWORD v4 = v2 + read_single<BYTE>(v2 + 4);
		return v2 + (256 * (read_single<BYTE>(v4 + 4 * v3 + 1) + ((read_single<BYTE>(v4 + 4 * v3 + 2) +
			(read_single<BYTE>(v4 + 4 * v3 + 3) << 8)) << 8)) + read_single<BYTE>(v4 + 4 * v3));
	}
}

bool initialize_sg_sigs() {
	auto result = external_batch_sigscan("Game.exe",
		{ "FC A1 ?? ?? ?? ?? 53", //dword_26EE718, phone state ptr, unk2_index
		"C1 02 51", //dword_18EC754, unk1
		"80 ?? ?? ?? ?? 40 50 FF", //dword_18EC778, unk2
		"34 85 ?? ?? ?? ?? 0F", //qword_26EE3E8, find_email_text
		"80 00 00 66 39 04 4D", //TextBuffer, markup_start
		"8B 75 F8 8B 1D" }); //dword_16E0690, markup_len
	phone_data_ptr = read_single<DWORD>(result[0] + 2);
	unk1_counter_ptr = read_single<DWORD>(result[1] + 5);
	unk2_email_data_ptr = read_single<DWORD>(result[2] + 1);
	unk3_find_email_ptr = read_single<DWORD>(result[3] + 2);
	markup_buffer_ptr = read_single<DWORD>(result[4] + 7);
	markup_len_ptr = read_single<DWORD>(result[5] + 5);

	return std::find(result.begin(), result.end(), 0) == result.end();
}

DWORD SGEmailText::get_phone_state() {
	const DWORD phone_state_ptr = read_single<DWORD>(phone_data_ptr);
	return read_single<DWORD>(phone_state_ptr + 0x6A48);
}

bool SGEmailText::extract_string() {
	const DWORD proc_base = get_executable_base();
	const DWORD phone_state_tmp = get_phone_state();
	DWORD unk2_index;

	switch (phone_state_tmp) {
	case PHONE_STATE_SENT:
	case PHONE_STATE_RCVD:
	case PHONE_STATE_RCVD_RESPONDABLE:
		unk2_index = read_single<DWORD>(read_single<DWORD>(phone_data_ptr) + 0x6A5C);
	break;
	case PHONE_STATE_SENDABLE:
		unk2_index = read_single<DWORD>(read_single<DWORD>(phone_data_ptr) + 0x6A84);
	break;
	default:
		// Don't overwrite text, but do nothing
		// For other screen transitions make it so that we don't re-paste the same thing over & over
		return false;
		break;
	}
	DWORD unk1 = read_single<DWORD>(unk1_counter_ptr);
	DWORD unk2 = read_single<DWORD>(unk2_email_data_ptr + (0x34 * unk2_index));
	std::wstring contact_tmp;
	std::wstring subject_tmp;
	std::wstring body_tmp;
	extract_mages_enc_string(find_email_text(unk1, unk2 + 1), contact_tmp);
	extract_mages_enc_string(find_email_text(unk1, unk2), subject_tmp);
	extract_mages_enc_string(find_email_text(unk1, unk2 + 2), body_tmp);

	if (body_tmp == body && 
		subject_tmp == subject && 
		contact_tmp == contact) {
		return false;
	}

	body = std::move(body_tmp);
	subject = std::move(subject_tmp);
	contact = std::move(contact_tmp);
	phone_state = phone_state_tmp;
	return true;
}

void SGEmailText::get_formatted_string(std::wstring& str_out) const {
	std::wostringstream str_builder(L"");
	str_builder << (phone_state == PHONE_STATE_SENT || phone_state == PHONE_STATE_SENDABLE ?
			L"Recipient: " : L"Sender: ") <<
		contact << L"\nSubject: " << subject << L"\nBody: " << body;
	str_out = std::move(str_builder.str());
}

bool SGMainText::extract_string() {
	constexpr DWORD PROBABLY_SAFE_LENGTH = 0x1000;
	constexpr DWORD SPEAKER_TAG = 1;
	constexpr DWORD TEXT_TAG = 2;
	constexpr DWORD MARKUP_END_TAG = 3;
	// Ruby format = text under ruby
	constexpr DWORD RUBY_FORMAT_START_TAG = 9;
	constexpr DWORD RUBY_TEXT_START_TAG = 10;
	constexpr DWORD RUBY_TEXT_END_TAG = 11;

	DWORD markup_len = read_single<DWORD>(markup_len_ptr);
	std::wostringstream str_builder(L"");

	std::wstring speaker_tmp;
	std::vector<SyllabizedWord> syllabized_words_tmp;
	std::wstring unformatted_text_tmp;
	bool ignore = false;

	std::wstring* target_str = &unformatted_text_tmp;
	
	// Hacky safeguard, won't change
	if (markup_len > PROBABLY_SAFE_LENGTH) {
		return false;
	}

	for (DWORD i = markup_buffer_ptr; i < (markup_buffer_ptr + 2 * markup_len); i += 2) {
		uint16_t markup_codepoint = read_single<uint16_t>(i);
		if (markup_codepoint & 0x8000) {
			*target_str = std::move(str_builder.str());
			switch (markup_codepoint & 0x7FFF) {
			case SPEAKER_TAG: 
				target_str = &speaker_tmp;
			break;
			case RUBY_TEXT_END_TAG:
			case TEXT_TAG:
				ignore = false;
				target_str = &unformatted_text_tmp;
			break;
			case RUBY_FORMAT_START_TAG:
				if (_ruby_enabled) {
					syllabized_words_tmp.emplace_back(unformatted_text_tmp.size());
					target_str = &syllabized_words_tmp[syllabized_words_tmp.size() - 1].word;
				}
			break;
			case RUBY_TEXT_START_TAG:
				if (_ruby_enabled) {
					target_str = &syllabized_words_tmp[syllabized_words_tmp.size() - 1].ruby;
				}
				else {
					ignore = true;
				}
			break;
			case MARKUP_END_TAG:
				// Verify proper markup length, otherwise race condition encountered
				if (i + 2 != (markup_buffer_ptr + 2 * markup_len)) {
					return false;
				}
			break;
			// Ignore unsupported formatting
			default:
				break;
			}
			// Reset stream and continue from last point (inefficient but oh well)
			str_builder = std::wostringstream(*target_str, std::ios::ate);
		}
		else if (!ignore) {
			str_builder << lookup_mages_codepoint(markup_codepoint);
		}
	}

	if (unformatted_text_tmp == unformatted_text &&
		syllabized_words_tmp == syllabized_words &&
		speaker_tmp == speaker) {
		return false;
	}
	
	speaker = std::move(speaker_tmp);
	syllabized_words = std::move(syllabized_words_tmp);
	unformatted_text = std::move(unformatted_text_tmp);
	return true;
}

void SGMainText::get_formatted_string(std::wstring& str_out) const {
	std::wostringstream str_builder(L"");
	if (!speaker.empty()) {
		str_builder << speaker << ": ";
	}

	if (_ruby_enabled) {
		for (size_t i = 0, ruby_idx = 0; i < unformatted_text.size(); i++) {
			if (ruby_idx < syllabized_words.size() &&
				syllabized_words[ruby_idx].insert_point == i) {
				str_builder << syllabized_words[ruby_idx].word << L"(" <<
					syllabized_words[ruby_idx].ruby << "L)";
				ruby_idx++;
			}
			str_builder << unformatted_text[i];
		}
	}
	else {
		str_builder << unformatted_text;
	}
	str_out = std::move(str_builder.str());
}