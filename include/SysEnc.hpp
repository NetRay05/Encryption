#pragma once

// Check if compiler supports int64_t and uint64_t
#if !defined(__UINT64_MAX__)
typedef long long int int64_t;
typedef unsigned long long int uint64_t;
#endif
 
// Check if compiler supports char16_t and char32_t
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 201112L))
typedef unsigned short char16_t;
typedef unsigned int char32_t;
#endif

// Define default type sizes if not provided by the compiler
#ifndef _INT64_T_
typedef long long int _INT64_T_;
#endif

#ifndef _UINT64_T_
typedef unsigned long long int _UINT64_T_;
#endif

// Define architecture-specific types
#if defined(__x86_64__) || defined(_M_X64) || defined(_LP64) || defined(__ia64__) || defined(__IA64__) // 64-bit architectures
#define _INT_64_T_ int64_t
#define _UINT_64_T_ uint64_t
#define _INT_32_T_ int32_t
#define _UINT_32_T_ uint32_t
#define _INT_16_T_ int16_t
#define _UINT_16_T_ uint16_t
#elif defined(__i386__) || defined(_M_IX86) || defined(__ILP32__) || defined(__386__) // 32-bit x86 architecture
#define _INT_32_T_ int32_t
#define _UINT_32_T_ uint32_t
#define _INT_16_T_ int16_t
#define _UINT_16_T_ uint16_t
#elif defined(__aarch64__) || defined(__arm64__) // 64-bit ARM architecture
#define _INT_64_T_ int64_t
#define _UINT_64_T_ uint64_t
#define _INT_32_T_ int32_t
#define _UINT_32_T_ uint32_t
#define _INT_16_T_ int16_t
#define _UINT_16_T_ uint16_t
#elif defined(__arm__) || defined(__arm32__) || defined(__thumb__) || defined(_ARM) || defined(_M_ARM) // 32-bit ARM architecture
#define _INT_32_T_ int32_t
#define _UINT_32_T_ uint32_t
#define _INT_16_T_ int16_t
#define _UINT_16_T_ uint16_t
#else
// Define default types for other architectures
#define _INT_64_T_ long long int
#define _UINT_64_T_ unsigned long long int
#define _INT_32_T_ int
#define _UINT_32_T_ unsigned int
#define _INT_16_T_ short int
#define _UINT_16_T_ unsigned short int
#endif

// Define platform-specific types
#ifdef _WIN32 // Windows
#define _CHAR_T_ char
#define _CHAR_16_T_ char16_t
#define _CHAR_32_T_ char32_t
#define _ICHAR_T_ signed char
#define _ICHAR_16_T_ signed char16_t
#define _ICHAR_32_T_ signed char32_t
#define _UCHAR_T_ unsigned char
#define _UCHAR_16_T_ unsigned char16_t
#define _UCHAR_32_T_ unsigned char32_t
#else // Linux and macOS
#define _CHAR_T_ char
#define _CHAR_16_T_ char16_t
#define _CHAR_32_T_ char32_t
#define _ICHAR_T_ signed char
#define _ICHAR_16_T_ signed char16_t
#define _ICHAR_32_T_ signed char32_t
#define _UCHAR_T_ unsigned char
#define _UCHAR_16_T_ unsigned char16_t
#define _UCHAR_32_T_ unsigned char32_t
#endif

// include header file containing all required program lib headers
#ifndef __GLOBAL_HEADER__
#include "header.hpp"
#endif

// platform specific implementation for Linux
#if defined(__linux__)

#include <cstdio>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#define PATH_SEPARATOR (const char *)"/"
#define ROOT_DIRECTORY std::string("/home")
#define _CHAR_T_ char

// platform specific implementation for Apple
#elif defined(__APPLE__)

#include <pwd.h>
#include <sys/types.h>
#define PATH_SEPARATOR (const char *)"/"
#define ROOT_DIRECTORY std::string("/Users")
#define _CHAR_T_ char

// platform specific implementation for Windows
#elif defined(_WIN32) || defined(_WIN64)

#include <Windows.h>
#define PATH_SEPARATOR (const char *)"\\"
#define ROOT_DIRECTORY std::string("C:\\Users")

#endif

// End Platform specific region

// get current user logged for file streaming operations in order to register env vars
const std::string get_logged_in_username()
{
    std::string _user;
#if defined(__linux__) || defined(__APPLE__)
    _user = std::string((getpwuid((uid_t)geteuid()))->pw_name);
#elif defined(_WIN32) || defined(_WIN64)
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    _user = username;
#endif
    return _user.empty() ? "" : _user;
};

// generate random pseudo numbers for file creation and registration
const std::string gen_sec_block_x_location(const char *_prefix, const char *_suffix)
{
    std::random_device seeder;
    std::mt19937 generator(seeder.entropy() ? seeder() : time(nullptr));
    std::uniform_int_distribution<unsigned long long> distributor(999999999, 999999999999999999);
    return std::string(_prefix) + std::to_string(distributor(generator)) + _suffix;
};

void logInfo() {};
template <typename mT, typename... tArgs> void logInfo(mT msg, tArgs... m_list)
{
#if defined(__linux__)
    std::cout << "\x1b[32m" << msg;
    logInfo(std::forward<tArgs>(m_list)...);
    std::cout << "\x1b[0m";
#elif defined(__APPLE__)
    std::cout << "\033[32m" << msg;
    logInfo(std::forward<tArgs>(m_list)...);
    std::cout << "\033[0m";
#elif defined(_WIN32) || defined(_WIN64)
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    std::cout << msg;
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    logInfo(std::forward<tArgs>(m_list)...);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#endif
};
void logWarn() {};
template <typename mT, typename... tArgs> void logWarn(mT msg, tArgs... m_list)
{
#if defined(__linux__)
    std::cout << "\x1b[33m" << msg;
    logInfo(std::forward<tArgs>(m_list)...);
    std::cout << "\x1b[0m";
#elif defined(__APPLE__)
    std::cout << "\033[32m" << msg;
    logInfo(std::forward<tArgs>(m_list)...);
    std::cout << "\033[0m";
#elif defined(_WIN32) || defined(_WIN64)
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);
    std::cout << msg;
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);
    logInfo(std::forward<tArgs>(m_list)...);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#endif
};
void logError() {};
template <typename mT, typename... tArgs> void logError(mT msg, tArgs... m_list)
{
#if defined(__linux__)
    std::cout << "\x1b[31m" << msg;
    logInfo(std::forward<tArgs>(m_list)...);
    std::cout << "\x1b[0m";
#elif defined(__APPLE__)
    std::cout << "\033[31m" << msg;
    logInfo(std::forward<tArgs>(m_list)...);
    std::cout << "\033[0m";
#elif defined(_WIN32) || defined(_WIN64)
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    std::cout << msg;

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    logInfo(std::forward<tArgs>(m_list)...);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#endif
};

#if defined(PATH_SEPARATOR)

#define LOGGED_USER_ID get_logged_in_username()
#define BASE_DIRECTORY (ROOT_DIRECTORY + PATH_SEPARATOR) + LOGGED_USER_ID
#define KEY_REGISTRY_FOLDER_ID "rkdata"
#define REGISTRY_ADDRESS_PATH BASE_DIRECTORY + PATH_SEPARATOR + KEY_REGISTRY_FOLDER_ID
#define RECOVERY_MODE_PATH REGISTRY_ADDRESS_PATH + PATH_SEPARATOR + ".rec_mode.txt"
#define TARGET_ADDRESS_PATH (REGISTRY_ADDRESS_PATH + PATH_SEPARATOR) + "._tgt0x0349343clrengtr7fg0923kjw.txt"
#define SECURE_GEN_KEY_REF (REGISTRY_ADDRESS_PATH + PATH_SEPARATOR) + "._krefx043nksdf3SFdjerIdsope30fkdl.txt"
#define SECURE_GEN_IV_REF (REGISTRY_ADDRESS_PATH + PATH_SEPARATOR) + "._ivrefx0MSlre90Jdlfk3rje098325.txt"
#define SECURE_OWN_KEY_REF (REGISTRY_ADDRESS_PATH + PATH_SEPARATOR) + "._ownkrefx0dflkdf094r3j4pf43rfw.txt"
#define DEFAULT_SECURE_GEN_KEY_PATH REGISTRY_ADDRESS_PATH + PATH_SEPARATOR + gen_sec_block_x_location("._k", ".bin").data()
#define DEFAULT_SECURE_GEN_IV_PATH REGISTRY_ADDRESS_PATH + PATH_SEPARATOR + gen_sec_block_x_location("._iv", ".bin").data()
#define DEFAULT_SECURE_OWN_KEY_PATH REGISTRY_ADDRESS_PATH + PATH_SEPARATOR + gen_sec_block_x_location("._ownk", ".bin").data()

#ifndef __SYSTEM_ENCRYPTION_FF__
#define __SYSTEM_ENCRYPTION_FF__ 1

namespace System
{

namespace
{
using Int16_t = _INT_16_T_;
using Int32_t = _INT_32_T_;
using Int64_t = _INT_64_T_;
using UInt16_t = _UINT_16_T_;
using UInt32_t = _UINT_32_T_;
using UInt64_t = _UINT_64_T_;
using Char_t = _CHAR_T_;
using Char16_t = _CHAR_16_T_;
using Char32_t = _CHAR_32_T_;
using String_t = std::basic_string<Char_t>;
using StringView_t = std::basic_string_view<Char_t>;
}; // namespace

#define DEC_FILE_ID (const Char_t *)"dec"
#define ENC_FILE_ID (const Char_t *)"enc"
#define DEC_EXE_FILE_ID (const Char_t *)"dec.exe"
#define ENC_EXE_FILE_ID (const Char_t *)"enc.exe"

#define MAX_PATH_LENGTH (UInt16_t)300

enum class FileType
{
    REGULAR,
    BINARY
};

enum class FileRenameMode
{
    ENCRYPTION,
    DECRYPTION
};

enum ExecuteMode
{
    ATOMIC = 0x01,
    SILENT = 0x02,
    VERBOSE = 0x04,
    EASED = 0x08
};

enum class RecoveryMode
{
    CUSTOM_SUPPLY,
    GENERATE_SECURE,
    NONE
};

enum class WriteFileMode
{
    CREATE_NEW,
    NO_CREATE
};

typedef struct
{
    String_t path;
    String_t file;
} PathBlocks;

class Crypto
{
  public:
    static UInt16_t exeMode;
    static RecoveryMode recovery_mode;
    UInt32_t ID = __GenRandomNumber();
    static UInt64_t aggregation_size;
    static UInt16_t *with_backup;

    // Member Function Overloading
    explicit Crypto();
    Crypto(const Crypto &other);
    Crypto(Crypto &&other);
    Crypto &operator=(const Crypto &other);
    Crypto &operator=(Crypto &&other);
    const bool operator==(const Crypto &other);

    // Message Log Region
    [[maybe_unused]] inline static void LogMessage() __attribute__((hot, nothrow));
    template <typename mT, typename... tArgs> [[maybe_unused]] inline static void LogMessage(mT msg, tArgs... __mlist) __attribute__((hot, nothrow));
    [[maybe_unused]] inline static void LogWarning() __attribute__((hot, nothrow));
    template <typename mT, typename... tArgs> [[maybe_unused]] inline static void LogWarning(mT msg, tArgs... __mlist) __attribute__((hot, nothrow));
    [[maybe_unused]] inline static void LogError() __attribute__((hot, nothrow));
    template <typename mT, typename... tArgs> [[maybe_unused]] inline static void LogError(mT msg, tArgs... __mlist) __attribute__((hot, nothrow));

    // File Handling Region
    [[maybe_unused]] inline static void WriteFile(const StringView_t &file_name, const StringView_t &buffer, const WriteFileMode write_mode) __attribute__((hot));
    [[maybe_unused, nodiscard]] inline static const String_t ReadFile(const StringView_t &file_name) __attribute__((hot));
    [[maybe_unused, nodiscard]] inline static const bool RegistryPathExists() noexcept;
    [[maybe_unused, nodiscard]] inline static const bool RegistryPathCreate() noexcept;
    [[nodiscard]] inline static const bool FileExists(const StringView_t &file_name) noexcept;
    [[maybe_unused, nodiscard]] inline static const bool DirectoryExists(const StringView_t &dir_name);
    [[maybe_unused, nodiscard]] inline static const bool EncryptFile(const StringView_t &file_name, const CryptoPP::SecByteBlock &use_sec_key) __attribute__((hot));
    [[maybe_unused, nodiscard]] inline static const bool DecryptFile(const StringView_t &file_name, const CryptoPP::SecByteBlock &use_sec_key) __attribute__((hot));
    [[maybe_unused, nodiscard]] inline static const bool CreateBackup(const StringView_t &target);
    [[nodiscard]] static const std::vector<System::String_t> DirectoryAggregation(const StringView_t &target);
    [[nodiscard]] static const bool Rename(const System::StringView_t &file_name, const bool byte_plus) __attribute__((hot));
    [[maybe_unused, nodiscard]] inline static const String_t CreateTestDirectory(const StringView_t &dir_path, const std::initializer_list<String_t> test_files);

    // Supplier Region
    [[maybe_unused]] inline static void SetRecoveryMode(void) noexcept;
    [[maybe_unused, nodiscard]] inline static const String_t SetCustomKeyAddress() noexcept;
    [[maybe_unused, nodiscard]] inline static const String_t SetRecoveryKey() noexcept;
    [[maybe_unused, nodiscard]] inline static const String_t SetTargetPath() noexcept;
    [[maybe_unused, nodiscard]] inline static const bool Want2CreateBackup() noexcept;
    [[maybe_unused, nodiscard]] inline static const bool Approve() noexcept __attribute__((hot));

    // Key/Iv/Secrets/OpPath Block Region
    [[maybe_unused, nodiscard]] inline static const RecoveryMode GetRecoveryMode(void);
    [[maybe_unused, nodiscard]] inline static const String_t GetRecoveryKeyAddress();
    [[maybe_unused]] inline static void RecoveryKeyIntersectAndRegister(const StringView_t &raw_key);
    [[maybe_unused]] inline static std::optional<CryptoPP::SecByteBlock> RecoveryKeyIntersect(const StringView_t &raw_key);
    [[maybe_unused, nodiscard]] inline static const std::optional<CryptoPP::SecByteBlock> GetRecoveryKey();
    [[maybe_unused]] inline static void RegisterTargetPath(const StringView_t &target);
    [[nodiscard]] inline static const std::optional<String_t> GetTargetPath();
    [[maybe_unused, nodiscard]] inline static const bool IsKeySet();

    // Misc Region
    [[maybe_unused]] inline static void CondWait(const Int32_t _wtime) noexcept;
    [[maybe_unused]] inline void CliSetExeMode(const int argc, char **argv);

    ~Crypto();

  private:
    const UInt32_t __GenRandomNumber(void);
    [[maybe_unused, nodiscard]] static const PathBlocks __SplitPath(const StringView_t &target);
    static void __ByteShiftBlocks(const System::StringView_t &file_name, System::String_t &new_file_name, const bool _plus) __attribute__((hot, nothrow));
};

UInt16_t Crypto::exeMode = ExecuteMode::EASED | ExecuteMode::VERBOSE;
RecoveryMode Crypto::recovery_mode = RecoveryMode::NONE;
UInt64_t Crypto::aggregation_size = (UInt64_t)0;
UInt16_t *Crypto::with_backup = new UInt16_t(0);

}; // namespace System

#endif

#endif
