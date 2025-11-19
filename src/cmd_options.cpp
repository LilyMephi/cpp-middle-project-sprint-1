#include "cmd_options.h"

namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
      ("help,h", "produce help message")
      ("command,c", po::value<std::string>(&cmd_)->default_value("encrypt"), "command: encrypt, decrypt, checksum")
      ("input,i", po::value<std::string>(&inputFile_)->required(), "input file path")
      ("output,o", po::value<std::string>(&outputFile_)->default_value("output.txt"), "output file path")
      ("password,p", po::value<std::string>(&password_), "password");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc_), vm);

        if (argc == 1 || vm.count("help")) {
            std::cout << desc_ << "\n";
            return false;
        }

        po::notify(vm);
    } catch (const po::error &e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cerr << desc_ << "\n";
        return false;
    }
    if (!cmd_.empty()) {
        auto it = commandMapping_.find(cmd_);
        if (it != commandMapping_.end()) {
            command_ = it->second;
        } else {
            std::cerr << "Unknown command: " << cmd_ << "\n";
            std::cerr << desc_ << "\n";
            return false;
        }
    }
    return true;
}

}  // namespace CryptoGuard
