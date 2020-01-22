#include "mpk_util.h"

#include <algorithm>
#include <filesystem>
#include <iostream>

MpkFile::MpkFile(std::string&& path) :
	file_name(std::move(path)),
	mpk_file_stream(file_name, std::ios::binary)
{}

bool MpkFile::parse() {
	if (!mpk_file_stream.is_open()) {
		std::cout << "mpk file " << file_name << " not found" << std::endl;
		return false;
	}

	mpk_file_stream.seekg(0, mpk_file_stream.beg);

	char magic_number[4];
	mpk_file_stream.read(magic_number, 4);
	if (magic_number[0] != 'M' ||
		magic_number[1] != 'P' ||
		magic_number[2] != 'K' ||
		magic_number[3] != 0) {
		std::cout << "Invalid MPK file provided" << std::endl;
		return false;
	}

	// Version number? Have seen 00 00 00 02
	mpk_file_stream.ignore(4);

	int32_t file_table_size;
	mpk_file_stream.read(reinterpret_cast<char*>(&file_table_size), 4);
	file_table.resize(file_table_size);

	mpk_file_stream.ignore(0x34);
	
	// File table is an array, this should be safe
	mpk_file_stream.read(reinterpret_cast<char*>(file_table.data()), file_table.size() * sizeof(FileTableEntry));

	mpk_file_stream.seekg(0, mpk_file_stream.end);
	auto size = mpk_file_stream.tellg();

	// Basic checks to make sure the file table is valid
	for (FileTableEntry const& file : file_table) {
		if (static_cast<std::streampos>(file.file_offset) > size ||
			static_cast<std::streampos>(file.file_size) > size ||
			static_cast<std::streampos>(file.file_offset + file.file_size) > size) {
			return false;
		}
	}
	return true;
}

bool MpkFile::iterate_files(std::function<bool(FileTableEntry const&)> callback) const {
	for (FileTableEntry const& file : file_table) {
		if (!callback(file)) return true;
	}
	return false;
}

void MpkFile::dump_file(FileTableEntry const& entry, std::string const& out_dir) const {
	// dump in 4mb chunks
	constexpr size_t CHUNK_SZ = 1 << 21;

	mpk_file_stream.seekg(entry.file_offset, mpk_file_stream.beg);

	std::filesystem::path output_path(out_dir);
	output_path /= std::filesystem::path(entry.file_name);
	if (!std::filesystem::exists(output_path.parent_path())) {
		std::filesystem::create_directories(output_path.parent_path());
	}

	std::ofstream output(output_path.c_str(), std::ios::binary);
	std::vector<char> chunk;
	chunk.resize(CHUNK_SZ);
	uint64_t remaining_bytes = entry.file_size;
	while (remaining_bytes > CHUNK_SZ) {
		mpk_file_stream.read(chunk.data(), CHUNK_SZ);
		output.write(chunk.data(), CHUNK_SZ);
		remaining_bytes -= CHUNK_SZ;
	}
	if (remaining_bytes) {
		mpk_file_stream.read(chunk.data(), remaining_bytes);
		output.write(chunk.data(), remaining_bytes);
	}
	output.flush();
}