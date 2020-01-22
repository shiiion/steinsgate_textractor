#include <iostream>
#include <fstream>

#include "mpk_util.h"

enum ARGV {
	INVALID,
	LIST,
	DUMP,
	DUMP_F,
};

ARGV validate_args(int argc, char** argv) {
	if (argc < 3) {
		std::cout << "\nUsage: mpkextract path_to_mpk [-ls | -dp {dump_dir} | -f {file_name} {dump_dir}]" << std::endl;
		std::cout << "\t-ls: Lists all files in the mpk" << std::endl;
		std::cout << "\t-dp: Dumps all of the contents from the mpk to {dump_dir} (optional)" << std::endl;
		std::cout << "\t-f:  Dumps a single file {file_name} from the mpk to {dump_dir} (optional)" << std::endl;
		return INVALID;
	}
	
	if (!strncmp(argv[2], "-ls", 4)) {
		return LIST;
	}
	
	if (!strncmp(argv[2], "-dp", 4)) {
		return DUMP;
	}

	if (!strncmp(argv[2], "-f", 3)) {
		if (argc < 4) {
			std::cout << "Must specify a file to dump" << std::endl;
			return INVALID;
		}
		return DUMP_F;
	}
	std::cout << "Invalid option " << argv[2] << std::endl;
	return INVALID;
}

int run_list_files(MpkFile const& mpk_file) {
	std::cout << "Listing " << mpk_file.file_count() << " files for " << mpk_file.mpk_name() << std::endl;
	mpk_file.iterate_files([](FileTableEntry const& file) -> bool {
		std::cout << "File table index " << file.entry_num << ":" << std::endl <<
			"\tName: " << file.file_name << std::endl <<
			"\tOffset: " << std::hex << file.file_offset << std::endl <<
			"\tSize: " << std::hex << file.file_size << std::dec << std::endl;
		return true;
	});
	return 0;
}

int run_dump_all(MpkFile const& mpk_file, std::string const& dump_dir) {
	std::cout << "Dumping " << mpk_file.file_count() << " files for " << mpk_file.mpk_name() << std::endl;
	mpk_file.iterate_files([&](FileTableEntry const& file) -> bool {
		std::cout << "Dumping " << file.file_name << std::endl;
		mpk_file.dump_file(file, dump_dir);
		return true;
	});
	return 0;
}

int run_dump_single(MpkFile const& mpk_file, std::string const& target_file, std::string const& dump_dir) {
	std::cout << "Attempting to dump " << target_file << " from " << mpk_file.mpk_name() << std::endl;
	if (mpk_file.iterate_files([&](FileTableEntry const& file) -> bool {
		if (target_file == file.file_name) {
			std::cout << "Found " << target_file << ", dumping to " <<
				(dump_dir == "" ? "current directory" : dump_dir) << std::endl;
			mpk_file.dump_file(file, dump_dir);
			return false;
		}
		return true;
		})) {
		return 0;
	}
	std::cout << "Failed to find " << target_file << std::endl;
	return 1;
}

int main(int argc, char** argv) {
	ARGV option;
	if ((option = validate_args(argc, argv)) == INVALID) {
		return 1;
	}

	MpkFile mpk(argv[1]);
	if (!mpk.parse()) {
		return 1;
	}

	int return_code;
	switch (option) {
	case LIST:
		return_code = run_list_files(mpk);
		break;
	case DUMP:
		return_code = run_dump_all(mpk, argc >= 4 ? argv[3] : "");
		break;
	case DUMP_F:
		return_code = run_dump_single(mpk, argv[3], argc >= 5 ? argv[4] : "");
		break;
	default:
		return_code = 1;
		break;
	}
	return return_code;
}