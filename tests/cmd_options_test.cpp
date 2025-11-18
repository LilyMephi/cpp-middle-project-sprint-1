#include "cmd_options.h"
#include <gtest/gtest.h>

std::vector<char *> make_argv(const std::vector<std::string> &args) {
    std::vector<char *> argv;
    for (const auto &s : args) {
        argv.push_back(const_cast<char *>(s.c_str()));
    }
    return argv;
}

TEST(ProgramOptionsTest, ShowsHelp) {
    CryptoGuard::ProgramOptions opts;
    auto argv = make_argv({"program", "--help"});
    EXPECT_FALSE(opts.Parse(static_cast<int>(argv.size()), argv.data()));
}

TEST(ProgramOptionsTest, MissingRequiredInput) {
    CryptoGuard::ProgramOptions opts;
    auto argv = make_argv({"program", "--command", "encrypt"});
    EXPECT_FALSE(opts.Parse(static_cast<int>(argv.size()), argv.data()));
}

TEST(ProgramOptionsTest, UnknownCommand) {
    CryptoGuard::ProgramOptions opts;
    auto argv = make_argv({"program", "--input", "file.txt", "--command", "unknown"});
    EXPECT_FALSE(opts.Parse(static_cast<int>(argv.size()), argv.data()));
}

TEST(ProgramOptionsTest, ParsesAllArgs) {
    CryptoGuard::ProgramOptions opts;
    auto argv = make_argv(
        {"program", "--input", "input.txt", "--output", "out.txt", "--command", "decrypt", "--password", "secret"});
    EXPECT_TRUE(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetInputFile(), "input.txt");
    EXPECT_EQ(opts.GetOutputFile(), "out.txt");
    EXPECT_EQ(opts.GetPassword(), "secret");
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptionsTest, DefaultsSetting) {
    CryptoGuard::ProgramOptions opts;
    auto argv = make_argv({"program", "-i", "file.txt", "-p", "12345"});
    EXPECT_TRUE(opts.Parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(opts.GetInputFile(), "file.txt");
    EXPECT_EQ(opts.GetOutputFile(), "output.txt");
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(opts.GetPassword(), "12345");
}