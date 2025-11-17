#include "cmd_options.h"

namespace po = boost::program_options;
namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
  std::string cmd;
  desc_.add_options()
    ("help", "produce help message")
    ("command", po::value<std::string>(&cmd)->default_value("encrypt"), "command")
    ("output", po::value<std::string>(&outputFile_)->default_value("output.txt"), "output file path");
    ("input", po::value<std::string>(&inputFile_)->required(), "input file path");
    ("password", po::value<std::string>(&password_)->required(), "password");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc_), vm);

  if (vm.count("help")) {
    std::cout << desc_ << std::endl;
    exit(-1);
  }

  po::notify(vm);
  if(!cmd.empty()){
    auto it = commandMapping_.find(cmd);
    if (it != commandMapping_.end()) {
      command_ = it->second;
    } else {
      std::cout << desc_ << "\n";
      std::cerr << "error while parse args" << std::endl;
      exit(-1);
    }
  }
}

}  // namespace CryptoGuard
