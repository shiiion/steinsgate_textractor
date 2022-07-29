#include "sg_text_extractor.h"

#include <sstream>

#include "process_utils.h"
#include "mages_string_map.h"

namespace {
	struct {
		DWORD phone_data_ptr = 0;
		DWORD unk1_counter_ptr = 0;
		DWORD unk2_email_data_ptr = 0;
		DWORD unk3_find_email_ptr = 0;
		DWORD main_text_hook_ptr = 0;
        DWORD string_lookup_scalar = 0;
	} sg_sigs;

	struct {
		DWORD phone_data_ptr = 0;
		DWORD send_message_lines = 0; // best guess at its purpose
		DWORD unk1_counter_ptr = 0;
		DWORD unk2_message_data_ptr = 0;
		DWORD unk2_unsent_message_ptr = 0;
		DWORD unk2_rine_message_ptr = 0;
		DWORD unk3_find_email_ptr = 0;
		DWORD rine_message_metadata_ptr = 0;
		DWORD okabe_rine_index_ptr = 0;
		DWORD contacts_rine_index_ptr = 0;
		DWORD contacts_metadata_ptr = 0;
		DWORD main_text_hook_ptr = 0;
		DWORD rine_message_count = 0;
	} sg0_sigs;

	Game game;

	template<typename T>
	T read_single(DWORD base) {
		SIZE_T t_size;
		T t_out;
		ReadProcessMemory(get_process_handle(), reinterpret_cast<LPCVOID>(base), &t_out, sizeof(T), &t_size);
		return t_out;
	}

    // mendokusai....
    // Returns the address of the terminal byte of the tag
    DWORD skip_achievement_tag(DWORD cur_index) {
        BYTE token = read_single<BYTE>(cur_index);
        if (!token) {
            return cur_index + 1;
        }
        do {
            if (token & 0x80) {
                switch (token & 0x60) {
                case 0:
                    cur_index += 2;
                    break;
                case 0x20:
                    cur_index += 3;
                    break;
                case 0x40:
                    cur_index += 4;
                    break;
                case 0x60:
                    cur_index += 5;
                    break;
                default:
                    // impossible
                    break;
                }
            } else {
                cur_index += 2;
            }
            token = read_single<BYTE>(cur_index);
        } while (token);
        // Just read a 00, return that position
        return cur_index;
    }

	void extract_mages_enc_string(DWORD string_start,
								  std::wstring* unformatted_text,
								  std::vector<SyllabizedWord>* syllabized_words,
								  std::wstring* speaker) {
        // I hope this is correct
		constexpr DWORD SPEAKER_TAG = 1;
		constexpr DWORD TEXT_TAG = 2;
		constexpr DWORD MARKUP_END_TAG = 3;
        constexpr DWORD ACHIEVE_WORD_TAG = 4;
		// Ruby format = text under ruby
		constexpr DWORD RUBY_FORMAT_START_TAG = 9;
		constexpr DWORD RUBY_TEXT_START_TAG = 10;
		constexpr DWORD RUBY_TEXT_END_TAG = 11;

		std::wostringstream str_builder;
		BYTE token_val = read_single<BYTE>(string_start);
		DWORD cur_index = string_start;
		std::wstring* target_str = unformatted_text;

		for (DWORD cur_index = string_start; token_val != 0xFF;) {
			if (!(token_val & 0x80)) {
				if (target_str) {
					*target_str = std::move(str_builder.str());
				}
				switch (token_val & 0x7F) {
				case SPEAKER_TAG:
					target_str = speaker;
					break;
				case RUBY_TEXT_END_TAG:
				case TEXT_TAG:
					target_str = unformatted_text;
					break;
                case ACHIEVE_WORD_TAG:
                    cur_index = skip_achievement_tag(cur_index + 1);
                    break;
				case RUBY_FORMAT_START_TAG:
					if (syllabized_words) {
						syllabized_words->emplace_back(unformatted_text->size());
						target_str = &(*syllabized_words)[syllabized_words->size() - 1].word;
					}
					break;
				case RUBY_TEXT_START_TAG:
					if (syllabized_words) {
						target_str = &(*syllabized_words)[syllabized_words->size() - 1].ruby;
					}
					break;
				case MARKUP_END_TAG:
					// Ignore unsupported formatting
					break;
				default:
					break;
				}
				// Reset stream and continue from last point (inefficient but oh well)
				str_builder = std::wostringstream(*target_str, std::ios::ate);
			}
			else if (target_str) {
				uint16_t markup_codepoint = (static_cast<uint16_t>(token_val & 0x7F) << 8) |
					read_single<BYTE>(++cur_index);
				str_builder << lookup_mages_codepoint(markup_codepoint);
			}
			++cur_index;
			token_val = read_single<BYTE>(cur_index);
		}
        if (target_str) {
            *target_str = std::move(str_builder.str());
        }
	}

	// Stolen from IDA decomp, this fn is an absolute mess, appears in both games
	DWORD find_email_text(DWORD unk1, DWORD unk2, DWORD unk3) {
		const DWORD v2 = read_single<DWORD>(unk3 + (unk1 * 4));
		const DWORD v3 = unk2 + ((read_single<BYTE>(v2 + 5) + ((read_single<BYTE>(v2 + 6) + (read_single<BYTE>(v2 + 7) << 8)) << 8)) << 6);
		const DWORD v4 = v2 + read_single<BYTE>(v2 + 4);
		return v2 + (256 * (read_single<BYTE>(v4 + 4 * v3 + 1) + ((read_single<BYTE>(v4 + 4 * v3 + 2) +
			(read_single<BYTE>(v4 + 4 * v3 + 3) << 8)) << 8)) + read_single<BYTE>(v4 + 4 * v3));
	}

	bool initialize_sg_sigs() {
		auto result = external_batch_sigscan("Game.exe", ".text",
			{ "FC A1 ?? ?? ?? ?? 53", //dword_26EE718, phone state ptr, unk2_index
			"C1 02 51", //dword_18EC754, unk1
			"80 ?? ?? ?? ?? 40 50 FF", //dword_18EC778, unk2
			"34 85 ?? ?? ?? ?? 0F", //qword_26EE3E8, find_email_text
			"FF FF 00 00 E8 ?? ?? ?? ?? 8B 87 4C", //main_text_ptr
            "8B 80 5C 6A 00 00 8D 0C C5 00 00 00 00 2B C8" }); //slight difference between s;g and darling's embrace
		sg_sigs.phone_data_ptr = read_single<DWORD>(result[0] + 2);
		sg_sigs.unk1_counter_ptr = read_single<DWORD>(result[1] + 5);
		sg_sigs.unk2_email_data_ptr = read_single<DWORD>(result[2] + 1);
		sg_sigs.unk3_find_email_ptr = read_single<DWORD>(result[3] + 2);
		sg_sigs.main_text_hook_ptr = result[4] + 36;
        sg_sigs.string_lookup_scalar = (result[5] ? 0x38 : 0x34);
        // "fake" result[5]
        result[5] = 1;

		return std::find(result.begin(), result.end(), 0) == result.end();
	}

	bool initialize_sg0_sigs() {
		auto result = external_batch_sigscan("Game.exe", ".text",
			{ "A1 ?? ?? ?? ?? 83 B8 20", //dword_2E3A9BC, phone state ptr
			"F7 E9 A1", //zero if sending sticker message (or some other stuff)
			"03 C1 50 FF 35", //unk1
			"8B 4D 08 A1 ?? ?? ?? ?? 03 C1", //unk2
			"A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 50 FF 35", //unk2 unsent message
			"8B 82 ?? ?? ?? ?? 8D", //RINE message 
			"56 8B 34 85 ?? ?? ?? ?? 0F", //find_email_text
			"03 C8 8D 14 8D", //RINE message metadata?
			"83 BE ?? ?? ?? ?? 0F 53 8B 1D", //okabe rine index?
			"89 8A ?? ?? ?? ?? 3B 0D", //other contact rine index?
			"FF 34 DD ?? ?? ?? ?? FF", //rine contact metadata?
			"8B 45 E0 89 87 4C 01 00 00 68 02 05 00 00", //main_text_ptr
			"8B 4D 10 53 56 57 8B 3D" }); //message_count
		sg0_sigs.phone_data_ptr = read_single<DWORD>(result[0] + 1);
		sg0_sigs.send_message_lines = read_single<DWORD>(result[1] + 3);
		sg0_sigs.unk1_counter_ptr = read_single<DWORD>(result[2] + 5);
		sg0_sigs.unk2_message_data_ptr = read_single<DWORD>(result[3] + 4);
		sg0_sigs.unk2_unsent_message_ptr = read_single<DWORD>(result[4] + 1);
		sg0_sigs.unk2_rine_message_ptr = read_single<DWORD>(result[5] + 2);
		sg0_sigs.unk3_find_email_ptr = read_single<DWORD>(result[6] + 4);
		sg0_sigs.rine_message_metadata_ptr = read_single<DWORD>(result[7] + 5);
		sg0_sigs.okabe_rine_index_ptr = read_single<DWORD>(result[8] + 2);
		sg0_sigs.contacts_rine_index_ptr = read_single<DWORD>(result[9] + 2);
		sg0_sigs.contacts_metadata_ptr = read_single<DWORD>(result[10] + 3);
		sg0_sigs.main_text_hook_ptr = result[11] + 0x39;
		sg0_sigs.rine_message_count = read_single<DWORD>(result[12] + 8);

		return std::find(result.begin(), result.end(), 0) == result.end();
	}
}

Game initialize_sigs() {
	auto result = external_batch_sigscan("Game.exe", ".text",
		{ "FF 34 DD ?? ?? ?? ?? FF", // Should only be valid for S;G0
			"80 ?? ?? ?? ?? 40 50 FF" }); // Should only be valid for S;G
	if (result[0]) {
		return game = (initialize_sg0_sigs() ? SG0 : INVALID);
	}
	else if (result[1]) {
		return game = (initialize_sg_sigs() ? SG : INVALID);
	}
	return INVALID;
}

DWORD SGEmailText::get_phone_state() {
	const DWORD phone_state_ptr = read_single<DWORD>(sg_sigs.phone_data_ptr);
	return read_single<DWORD>(phone_state_ptr + 0x6A48);
}

bool SGEmailText::extract_string() {
	const DWORD phone_state_tmp = get_phone_state();
	DWORD unk2_index;

	switch (phone_state_tmp) {
	case PHONE_STATE_SENT:
	case PHONE_STATE_RCVD:
	case PHONE_STATE_RCVD_RESPONDABLE:
		unk2_index = read_single<DWORD>(read_single<DWORD>(sg_sigs.phone_data_ptr) + 0x6A5C);
	break;
	case PHONE_STATE_SENDABLE:
		unk2_index = read_single<DWORD>(read_single<DWORD>(sg_sigs.phone_data_ptr) + 0x6A84);
	break;
	default:
		// Don't overwrite text, but do nothing
		// For other screen transitions make it so that we don't re-paste the same thing over & over
		return false;
		break;
	}
	DWORD unk1 = read_single<DWORD>(sg_sigs.unk1_counter_ptr);
	DWORD unk2 = read_single<DWORD>(sg_sigs.unk2_email_data_ptr + (sg_sigs.string_lookup_scalar * unk2_index));
	std::wstring contact_tmp;
	std::wstring subject_tmp;
	std::wstring body_tmp;
	extract_mages_enc_string(
		find_email_text(unk1, unk2 + 1, sg_sigs.unk3_find_email_ptr),
		&contact_tmp,
		nullptr,
		nullptr);
	extract_mages_enc_string(
		find_email_text(unk1, unk2, sg_sigs.unk3_find_email_ptr),
		&subject_tmp,
		nullptr,
		nullptr);
	extract_mages_enc_string(
		find_email_text(unk1, unk2 + 2, sg_sigs.unk3_find_email_ptr), 
		&body_tmp,
		nullptr,
		nullptr);

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

DWORD SG0RINEMessage::get_phone_state() {
	const DWORD phone_state_ptr = read_single<DWORD>(sg0_sigs.phone_data_ptr);
	return read_single<DWORD>(phone_state_ptr + 0x6728);
}

bool SG0RINEMessage::extract_string() {
	const DWORD phone_state = get_phone_state();
	if (phone_state != PHONE_STATE_RINE && phone_state != PHONE_STATE_RINE_RESPOND) {
		last_message_index = 0;
		return false;
	}
	int message_count = get_message_count();
	bool message_parsed = false;
	if (last_message_index < message_count) {
		DWORD msg_metadata = read_single<DWORD>(sg0_sigs.rine_message_metadata_ptr + 0x74 * last_message_index);
		if (!(msg_metadata & 0xF)) {
			DWORD unk1 = read_single<DWORD>(sg0_sigs.unk1_counter_ptr);
			{
				DWORD unk2 = read_single<DWORD>(last_message_index * 0x74 + sg0_sigs.unk2_rine_message_ptr);
				unk2 += read_single<DWORD>(sg0_sigs.unk2_message_data_ptr);
				extract_mages_enc_string(
					find_email_text(unk1, unk2, sg0_sigs.unk3_find_email_ptr),
					&message,
					nullptr,
					nullptr);
			}
			{
				DWORD unk2_index = sg0_sigs.okabe_rine_index_ptr;
				if (read_single<DWORD>(sg0_sigs.contacts_rine_index_ptr + 0x74 * last_message_index) <= 0xF) {
					unk2_index = read_single<DWORD>(sg0_sigs.contacts_rine_index_ptr + 0x74 * last_message_index);
				}
				DWORD unk2 = read_single<DWORD>(sg0_sigs.contacts_metadata_ptr + 8 * unk2_index);
				extract_mages_enc_string(
					find_email_text(unk1, unk2, sg0_sigs.unk3_find_email_ptr),
					&sender_name,
					nullptr,
					nullptr);

			}
			message_parsed = true;
		}
		last_message_index++;
	}
	
	return message_parsed;
}

void SG0RINEMessage::get_formatted_string(std::wstring& str_out) const {
	std::wostringstream str_builder(L"");
	str_builder << L"RINE message from " << sender_name << L": " << message;
	str_out = std::move(str_builder.str());
}

int SG0RINEMessage::get_message_count() const {
	return read_single<int>(sg0_sigs.rine_message_count);
}

bool SG0RINEConversation::extract_string() {
	const DWORD phone_state = get_phone_state();
	if (phone_state != PHONE_STATE_RINE && phone_state != PHONE_STATE_RINE_RESPOND) {
		last_message_index = 0;
		last_copy_index = 0;
		all_senders.clear();
		all_messages.clear();
		return false;
	}

	bool new_message = false;
	while (last_message_index < get_message_count()) {
		if (SG0RINEMessage::extract_string()) {
			all_senders.emplace_back(sender_name);
			all_messages.emplace_back(message);
			new_message = true;
		}
	}
	return new_message;
}

void SG0RINEConversation::get_formatted_string(std::wstring& str_out) const {
	std::wostringstream str_builder(L"");
	for (int i = last_copy_index; i < all_senders.size(); i++) {
		str_builder << L"RINE message from " << all_senders[i] << L": " << all_messages[i];
		if (i + 1 < all_senders.size()) {
			str_builder << L"\n";
		}
	}
	last_copy_index = all_senders.size();
	str_out = std::move(str_builder.str());
}

bool SG0RINESendableMessage::extract_string() {
	const DWORD phone_state = SG0RINEMessage::get_phone_state();
	if (phone_state != SG0RINEMessage::PHONE_STATE_RINE &&
		phone_state != SG0RINEMessage::PHONE_STATE_RINE_RESPOND) {
		return false;
	}

	std::wstring sendable_message_tmp;
	if (read_single<DWORD>(sg0_sigs.send_message_lines)) {
		DWORD unk1 = read_single<DWORD>(sg0_sigs.unk1_counter_ptr);
		DWORD unk2 = read_single<DWORD>(sg0_sigs.unk2_message_data_ptr) +
			read_single<DWORD>(sg0_sigs.unk2_unsent_message_ptr);
		extract_mages_enc_string(find_email_text(unk1, unk2, sg0_sigs.unk3_find_email_ptr),
			&sendable_message_tmp,
			nullptr,
			nullptr);
	}
	else {
		return false;
	}
	
	if (sendable_message == sendable_message_tmp) {
		return false;
	}
	sendable_message = std::move(sendable_message_tmp);
	return true;
}

void SG0RINESendableMessage::get_formatted_string(std::wstring& str_out) const {
	std::wostringstream str_builder(L"");
	str_builder << L"Sendable message: " << sendable_message;
	str_out = std::move(str_builder.str());
}

// Hooks right after call to string lookup function when next main text is displayed
// copies the string pointer to an allocated page for us to grab
JmpHook SGMainText::extract_hook = JmpHook(
	{
		0xA3, 0x00, 0x00, 0x00, 0x00,				// mov dword ptr [??], eax
		0x83, 0x87, 0x4C, 0x01, 0x00, 0x00, 0x02,	// add dword ptr [edi + 0x14C], 2
		0xE9, 0x00, 0x00, 0x00, 0x00				// jmp ??
	});
DWORD SGMainText::text_ptr_page = 0;

void SGMainText::install_text_hook() {
	text_ptr_page = allocate_page();
	extract_hook.fill_dword(text_ptr_page, 1);
	DWORD hook_instr_address = (game == SG ? sg_sigs.main_text_hook_ptr : sg0_sigs.main_text_hook_ptr);
	extract_hook.fill_jmp(hook_instr_address + 7, 13);
	extract_hook.insert_hook(hook_instr_address, 7);
}

bool SGMainText::extract_string() {
	DWORD main_text_lookup = read_single<DWORD>(text_ptr_page);
	if (!main_text_lookup) {
		return false;
	}
	std::wstring speaker_tmp;
	std::vector<SyllabizedWord> syllabized_words_tmp;
	std::wstring unformatted_text_tmp;

	extract_mages_enc_string(main_text_lookup,
		&unformatted_text_tmp,
		(_ruby_enabled ? &syllabized_words_tmp : nullptr),
		&speaker_tmp);

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
		str_builder << speaker << L": ";
	}

	if (_ruby_enabled) {
		for (size_t i = 0, ruby_idx = 0; i < unformatted_text.size(); i++) {
			while (ruby_idx < syllabized_words.size() &&
				syllabized_words[ruby_idx].insert_point == i) {
				str_builder << syllabized_words[ruby_idx].word << L"(" <<
					syllabized_words[ruby_idx].ruby << L")";
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