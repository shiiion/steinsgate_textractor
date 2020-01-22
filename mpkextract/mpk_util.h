#pragma once

#include <fstream>
#include <functional>
#include <string>
#include <vector>

struct FileTableEntry { // size: 0x100
	uint8_t unk1[4];
	uint32_t entry_num;
	uint64_t file_offset;
	uint64_t file_size;
	uint64_t file_size_2; // Not sure what it's for
	// This may not be correct, but since file_name includes a rel. path, I'm guessing it's OK?
	char file_name[0x100 - 0x20];
};

class MpkFile {
public:
	MpkFile(std::string&& path);
	bool parse();
	bool iterate_files(std::function<bool(FileTableEntry const&)> callback) const;
	size_t file_count() const { return file_table.size(); }
	std::string const& mpk_name() const { return file_name; }
	void dump_file(FileTableEntry const& entry, std::string const& out_dir) const;

private:
	std::string file_name;
	std::vector<FileTableEntry> file_table;
	mutable std::ifstream mpk_file_stream;
};