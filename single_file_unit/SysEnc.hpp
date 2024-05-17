#pragma once

#ifndef _GLOBAL_HEADER_
#define _GLOBAL_HEADER_ 1

// Common includes
#include <chrono>
#include <cstdio>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <cstring>
#include <typeinfo>
#include <unordered_set>
#include <thread>
#include <optional>
#include <sstream>
#include <zlib.h>
#include <memory>
#include <zip.h>

// Platform-specific includes
#ifdef _WIN32 // Windows
    #include <Windows.h>
    #include <Lmcons.h> // For UNLEN
    #include <filesystem> // Use experimental/filesystem for older versions of MSVC
#elif defined(__linux__) || defined(__APPLE__) // Linux or macOS
    #include <pwd.h>
    #include <sys/types.h>
    #include <unistd.h>
    #include <filesystem>
#endif

// Encryption Libraries
#include <crypto++/aes.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/rsa.h>
#include <crypto++/sha.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/secblock.h>

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
#define _UCHAR_T_ unsigned char
#else // Linux and macOS
#define _CHAR_T_ char
#define _UCHAR_T_ unsigned char
#define _CHAR_16_T_ char16_t
#define _CHAR_32_T_ char32_t
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
#define DEFAULT_SSL_KEY_SIZE (UInt16_t)2048

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
using UChar_t = _UCHAR_T_;
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
    String_t path{};
    String_t file{};
} PathBlocks;

typedef struct {
    String_t private_key{};
    String_t public_key{};
    UInt16_t key_size{2048};
} SslKeyBlock;

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

    // Deflate/Inflate Compression/Decompression
    [[maybe_unused]] inline static void CompressFile(const StringView_t &file_path, const StringView_t &destination_zip_path);
    [[maybe_unused]] inline static void DecompressFile(const StringView_t &zip_file, const StringView_t &dest_file);

    // SSL Symmetric/Asymmetric Encryption
    [[maybe_unused, nodiscard]] inline static const bool GenSslKeyPair(const StringView_t &private_key_path, const StringView_t &public_key_path, const UInt16_t key_size);
    [[maybe_unused, nodiscard]] inline static const bool GenSslKeyPair(const SslKeyBlock key_info);

    // Misc Region
    [[maybe_unused]] inline static void CondWait(const Int32_t _wtime) noexcept;
    [[maybe_unused]] inline void CliSetExeMode(const int argc, char **argv);
    [[maybe_unused, nodiscard]] inline static const SslKeyBlock CliSslFlagCollect(const int argc, char **argv);

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



// --------------------------------------------------------------------------- // 


/*                        Constructor/Destructor/Overloaders                         *\
\*************************************************************************************/

System::Crypto::Crypto(){};

System::Crypto::Crypto(const System::Crypto &other)
{
    this->ID = other.ID;
};

System::Crypto::Crypto(System::Crypto &&other)
{
    this->ID = other.ID;
    other.ID = 0;
};

System::Crypto &System::Crypto::operator=(const System::Crypto &other)
{
    if (*this == other)
        return *this;

    this->ID = other.ID;
    return *this;
};

System::Crypto &System::Crypto::operator=(System::Crypto &&other)
{
    if (*this == other)
        return *this;

    this->ID = other.ID;
    other.ID = 0;
    return *this;
};

const bool System::Crypto::operator==(const System::Crypto &other)
{
    return (this->ID == other.ID);
}

// Destructor
System::Crypto::~Crypto()
{
    this->ID = 0;
};

/*                           Message Log Routines                            *\
\*****************************************************************************/

void System::Crypto::LogMessage() {};
template <typename mT, typename... tArgs> void System::Crypto::LogMessage(mT msg, tArgs... m_list)
{
    if (exeMode & ExecuteMode::VERBOSE)
        logInfo(msg, m_list...);
};
void System::Crypto::LogWarning() {};
template <typename mT, typename... tArgs> void System::Crypto::LogWarning(mT msg, tArgs... m_list)
{
    if (exeMode & ExecuteMode::VERBOSE)
        logWarn(msg, m_list...);
};
void System::Crypto::LogError() {};
template <typename mT, typename... tArgs> void System::Crypto::LogError(mT msg, tArgs... m_list)
{
    if (exeMode & ExecuteMode::VERBOSE)
        logError(msg, m_list...);
};

/*                               File Handlers                               *\
\*****************************************************************************/

/**
 * Write *buffer* into *file_name* using binary mode
 * @param const StringView_t&
 * @param const StringView_t&
 * @returns void
 */
[[maybe_unused]] void System::Crypto::WriteFile(const StringView_t &file_name, const StringView_t &buffer, const WriteFileMode write_mode)
{
    if (!FileExists(file_name) && write_mode == WriteFileMode::NO_CREATE) [[unlikely]]
    {
        throw std::runtime_error(String_t(file_name.data()) + " does not exists!");
    }
    std::ofstream fWriter(file_name.data(), std::ios::binary);
    if (!fWriter.is_open()) [[unlikely]]
    {
        throw std::runtime_error(strerror(errno));
    }
    if (fWriter.good()) [[likely]]
    {
        fWriter.write(buffer.data(), buffer.size());
    }
    fWriter.close();
};

/**
 * Read Content From *file_name* and return it as String_t
 * @param const StringView_t&
 * @returns const String_t
 */
[[maybe_unused, nodiscard]] const System::String_t System::Crypto::ReadFile(const StringView_t &file_name)
{
    String_t fContent;

    std::ifstream fRead(file_name.data(), std::ios::binary);
    if (!fRead.is_open()) [[unlikely]]
        throw std::runtime_error(String_t("Cannot read file!") + strerror(errno));

    fRead.seekg(0, std::ios::end);
    const std::streamsize file_size = fRead.tellg();
    fContent.resize(file_size);
    fRead.seekg(0, std::ios::beg);

    if (fRead.good()) [[likely]]
    {
        fRead.read(fContent.data(), file_size);
    }
    fRead.close();
    return fContent;
};

/**
 * Check if REQUIRED Registry path is set/created, return true if found, false otherwise
 * @returns const bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::RegistryPathExists() noexcept
{
    return (bool)(std::filesystem::exists(REGISTRY_ADDRESS_PATH) && std::filesystem::is_directory(REGISTRY_ADDRESS_PATH));
};

/**
 * Create Registry Path for storing registry keys used for encryption and decryption operations, returns true if created, false otherwise.
 * @returns const bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::RegistryPathCreate() noexcept
{
    return (bool)(std::filesystem::create_directory(REGISTRY_ADDRESS_PATH) || std::filesystem::create_directories(REGISTRY_ADDRESS_PATH));
};

[[nodiscard]] const bool System::Crypto::FileExists(const StringView_t &file_name) noexcept
{
    std::filesystem::path fileAddress = file_name.data();
    return (bool)(std::filesystem::exists(fileAddress) && std::filesystem::is_regular_file(fileAddress));
};

[[maybe_unused, nodiscard]] const bool System::Crypto::DirectoryExists(const StringView_t &dir_name)
{
    return std::filesystem::exists(dir_name.data()) && std::filesystem::is_directory(dir_name.data());
};

/**
 * Encrypt file content, CBC/AES encryption mode, return true if encrypted, false otherwise
 * @param const StringView_t&
 * @param CryptoPP::SecByteBlock&
 * @returns bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::EncryptFile(const StringView_t &file_name, const CryptoPP::SecByteBlock &use_sec_key)
{
    try
    {
        if (file_name.empty() || !FileExists(file_name)) [[unlikely]]
            throw std::runtime_error("Cannot find file name to encrypt");
        else if (use_sec_key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) [[unlikely]]
            throw std::runtime_error("Encryption Secure Key Block Size is invalid!");

        CryptoPP::byte salt_value[CryptoPP::AES::DEFAULT_KEYLENGTH];

        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(salt_value, sizeof(salt_value));

        std::ifstream readCipher(file_name.data(), std::ios::binary);

        if (!readCipher.is_open()) [[unlikely]]
            throw std::runtime_error("Cannot Open file for reading!");

        std::stringstream buffer;
        buffer << readCipher.rdbuf();
        std::string plaintext = buffer.str();
        buffer.clear();
        readCipher.close();

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryptor;
        cbcEncryptor.SetKeyWithIV(use_sec_key, use_sec_key.size(), salt_value);

        String_t ciphertext;
        CryptoPP::StringSource(plaintext, true, new CryptoPP::StreamTransformationFilter(cbcEncryptor, new CryptoPP::StringSink(ciphertext)));

        std::ofstream writeCipher(file_name.data(), std::ios::binary | std::ios::out | std::ios::trunc);

        if (!writeCipher.is_open()) [[unlikely]]
            throw std::runtime_error("Cannot write encrypted cipher to file");

        writeCipher.write(reinterpret_cast<char *>(&salt_value), sizeof(salt_value));
        writeCipher.write(ciphertext.c_str(), ciphertext.size());

        writeCipher.close();

        CondWait(5000);
        LogMessage("[+] ", file_name.data(), " --> encrypted...\n");

        if (!System::Crypto::Rename(file_name.data(), true))
        {
            LogWarning("Cannot rename filename ", file_name, '\n');
        }

        return true;
    }
    catch (const CryptoPP::Exception &_e)
    {
        std::cerr << "Encryption CryptoException: " << _e.what() << '\n';
        return false;
    }
    catch (const std::runtime_error &_e)
    {
        std::cerr << "Encryption RuntimeError: " << _e.what() << '\n';
        return false;
    }
    catch (const std::exception &_e)
    {
        std::cerr << "Encryption Exception: " << _e.what() << '\n';
        return false;
    }
    return false;
};

/**
 * Decrypt file content, CBC/AES encryption mode, return true if decrypted, false otherwise
 * @param const StringView_t&
 * @param CryptoPP::SecByteBlock&
 * @returns bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::DecryptFile(const StringView_t &file_name, const CryptoPP::SecByteBlock &sec_key)
{
    try
    {

        if (file_name.empty() || !FileExists(file_name)) [[unlikely]]
            throw std::runtime_error("cannot find file for decryption!");
        else if (sec_key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH) [[unlikely]]
            throw std::runtime_error("Secure Key Block size is invalid!");

        CryptoPP::byte salt_value[CryptoPP::AES::DEFAULT_KEYLENGTH];

        std::ifstream readCipher(file_name.data(), std::ios::binary);

        if (!readCipher.is_open()) [[unlikely]]
            throw std::runtime_error("Cannot open file for decryption!");

        readCipher.read(reinterpret_cast<char *>(&salt_value), sizeof(salt_value));

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcDecryptor;
        cbcDecryptor.SetKeyWithIV(sec_key, sec_key.size(), salt_value);

        String_t ciphertext((std::istreambuf_iterator<char>(readCipher)), std::istreambuf_iterator<char>());
        String_t recovered_cipher;

        CryptoPP::StringSource(ciphertext, true, new CryptoPP::StreamTransformationFilter(cbcDecryptor, new CryptoPP::StringSink(recovered_cipher)));

        std::ofstream writeRecovered(file_name.data(), std::ios::binary | std::ios::out | std::ios::trunc);

        if (!writeRecovered.is_open()) [[unlikely]]
            throw std::runtime_error("Cannot write recovered cipher to owner file!");
        else if (recovered_cipher.empty()) [[unlikely]]
            throw std::runtime_error("Attempting Write decrypted Empty buffer to file!");

        writeRecovered.write(recovered_cipher.c_str(), recovered_cipher.size());
        writeRecovered.close();

        CondWait(5000);
        LogMessage("[+] ", file_name.data(), " --> decrypted...\n");

        if (!System::Crypto::Rename(file_name.data(), false))
        {
            LogWarning("Cannot rename filename ", file_name, '\n');
        }

        return true;
    }
    catch (const CryptoPP::Exception &_e)
    {
        std::cerr << "Decryption Error: Supplied Key Invalid!" << '\n';
        return false;
    }
    catch (const std::runtime_error &_e)
    {
        std::cerr << "Decryption RuntimeError: " << _e.what() << '\n';
        return false;
    }
    catch (const std::exception &_e)
    {
        std::cerr << "Decryption Exception: " << _e.what() << '\n';
        return false;
    }

    return false;
};

/**
 * Create a backup copy of the data to be encrypted, returns true if successfully backup, false otherwise.
 * @param const StringView_t& the target path to backup
 * @returns const bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::CreateBackup(const StringView_t &target)
{
    try
    {
        if (target.empty() || target[0] == ' ')
            return false;

        std::filesystem::path sourceDir = target.data();

        if (!std::filesystem::exists(sourceDir) || !std::filesystem::is_directory(sourceDir)) [[unlikely]]
            throw std::runtime_error(String_t("Directory ") + target.data() + " does not exists or not a dir!");

        LogMessage("Creating backup of resource: ", target.data(), '\n');

        String_t backupFolder = target.data();
        backupFolder += "-backup";

        std::filesystem::path backupPath = backupFolder;

        if (!std::filesystem::exists(backupPath)) [[unlikely]]
        {
            std::filesystem::create_directories(backupPath) || std::filesystem::create_directory(backupPath);
        }
        UInt64_t clone_count = 0;
        for (auto &entry : std::filesystem::recursive_directory_iterator(sourceDir))
        {
            std::filesystem::path relativePath = std::filesystem::relative(entry.path(), sourceDir);
            std::filesystem::path destinationPath = backupFolder / relativePath;
            if (std::filesystem::is_regular_file(entry)) [[likely]]
            {
                LogMessage("Cloning File ", entry.path(), '\n');
                std::filesystem::copy_file(entry.path(), destinationPath, std::filesystem::copy_options::overwrite_existing);
                ++clone_count;
            }
            else if (std::filesystem::is_directory(entry)) [[likely]]
            {
                LogMessage("Cloning Directory ", entry.path(), '\n');
                std::filesystem::create_directories(destinationPath);
            }
            else if (std::filesystem::is_symlink(entry)) [[unlikely]]
            {
                LogMessage("Cloning SymLink ", entry.path(), '\n');
                std::filesystem::copy(entry.path(), destinationPath, std::filesystem::copy_options::create_symlinks);
                ++clone_count;
            }
            CondWait(9000);
        }
        LogMessage("Cloned Total: ", aggregation_size, "/", clone_count, '\n');
        return clone_count == aggregation_size ? true : false;
    }
    catch (const std::exception &_e)
    {
        LogWarning("Error: cannot backup -> ", std::move(_e.what()));
        return false;
    }
    return false;
};

/**
 * Collect target entries and return vector containing all found entries.
 * @param const StringView_t& target
 * @returns std::vector<String_t>
 */
[[nodiscard]] const std::vector<System::String_t> System::Crypto::DirectoryAggregation(const System::StringView_t &target)
{
    std::vector<System::String_t> Aggregation;

    const std::filesystem::path ScanPath = target.data();
    if (std::filesystem::exists(ScanPath) & std::filesystem::is_directory(ScanPath)) [[likely]]
    {
        for (const std::filesystem::directory_entry &_aggr_entry : std::filesystem::recursive_directory_iterator(ScanPath))
        {
            if (!_aggr_entry.is_directory()) [[likely]]
            {
                LogMessage("[+] ", _aggr_entry.path().string().c_str(), '\n');
                CondWait(5000);
                Aggregation.push_back(_aggr_entry.path().c_str());
            }
        }
        LogMessage("Collected ", Aggregation.size(), " entries.\n");
        aggregation_size = Aggregation.size();
    }
    else if (std::filesystem::is_regular_file(ScanPath)) [[unlikely]]
    {
        Aggregation.push_back(target.data());
    }
    return Aggregation;
};

/**
 * Rename file name to a random generated value, returns true on success, false on failure.
 * @param const System::StringView_t& the file to rename
 * @param const bool if for encryption or decryption
 * @returns const bool
 */
[[nodiscard]] const bool System::Crypto::Rename(const System::StringView_t &file_name, const bool byte_plus)
{
    try
    {
        if (!file_name.empty() && file_name.size() < 300) [[likely]]
        {
            const PathBlocks pBlock = __SplitPath(file_name);

            if (!pBlock.file.empty() && !pBlock.path.empty()) [[likely]]
            {
                String_t new_file_name = pBlock.path.c_str();

                __ByteShiftBlocks(pBlock.file, new_file_name, byte_plus);

                if (std::rename(file_name.data(), new_file_name.c_str()) != 0)
                {
                    std::cerr << "Failed to rename file " << file_name << " -> " << strerror(errno) << '\n';
                }
            }
        }
    }
    catch (const std::runtime_error &_e)
    {
        return false;
    }
    catch (const std::exception &_e)
    {
        return false;
    }
    return true;
};

/**
 * Create a test directory with a list of files from test_files list, test_files entries must only contain file name without path,
 * and the dir_path value must be an absolute path to the test directory to create.
 * For example, dir_path = "/path/to/dir/test" and test_file = {"file1.txt", "file2.txt", ...}
 * @param const StringView_t& the directory path
 * @param const std::initializer_list<String_t> list of files to create into dir_path
 * @returns const bool if test directory was created or not
 */
[[maybe_unused, nodiscard]] const System::String_t System::Crypto::CreateTestDirectory(const StringView_t &dir_path, const std::initializer_list<String_t> test_files)
{
    String_t rVal;
    if (dir_path.empty())
    {
        LogWarning("Test Directory is empty!\n");
        return rVal;
    }
    if (test_files.size() == 0)
    {
        LogWarning("File list is empty, no files will be created..\n");
    }
    if (DirectoryExists(dir_path))
    {
        LogWarning("Directory already exists!\n");
        return rVal;
    }
    std::filesystem::create_directories(std::move(dir_path.data())) || std::filesystem::create_directory(std::move(dir_path.data()));
    if (DirectoryExists(dir_path.data()))
    {
        for (const String_t &new_file : test_files)
        {
            if (new_file.compare(".") == 0 || new_file.compare("..") == 0)
                continue;

            String_t entry_id = dir_path.data();
            entry_id += PATH_SEPARATOR;
            entry_id += std::move(new_file.c_str());
            LogMessage("Creating test file <", entry_id, ">...\n");
            std::ofstream createFile(entry_id.c_str());
            createFile << "Something in this file";
            createFile.close();
            if (FileExists(std::move(entry_id.c_str())))
            {
                LogMessage("File <", entry_id.c_str(), "> created!\n");
            }
        }
        rVal = dir_path;
    }
    else
    {
        LogError("Cannot find directory!");
    }
    return rVal;
};

/*                               Suppliers                                   *\
\*****************************************************************************/

[[maybe_unused]] void System::Crypto::SetRecoveryMode(void) noexcept
{
    LogMessage("Veryfing Registry Key Address...\n");
    if (!RegistryPathExists()) [[likely]]
    {
        LogMessage("Registry Path Not Found\n");
        if (!RegistryPathCreate()) [[unlikely]]
        {
            LogMessage("Cannot create Registry Path\n");
            return;
        }
        LogMessage("Registry Path Created\n");
    }

    String_t rec_mode;
    std::cout << "Choose Decryption Recovery Mode:\n1) Supply Your Own Recovery key\n2) Generate Secure Keys\n";
SetRecoveryMode:
    std::cout << "Select One [1/2] : ";
    std::cin >> rec_mode;
    if (rec_mode.compare("1") == 0) [[likely]]
    {
        recovery_mode = RecoveryMode::CUSTOM_SUPPLY;
        WriteFile(RECOVERY_MODE_PATH, "S", WriteFileMode::CREATE_NEW);
    }
    else if (rec_mode.compare("2") == 0) [[unlikely]]
    {
        recovery_mode = RecoveryMode::GENERATE_SECURE;
        WriteFile(RECOVERY_MODE_PATH, "G", WriteFileMode::CREATE_NEW);
    }
    else
    {
        goto SetRecoveryMode;
    }
};

[[maybe_unused, nodiscard]] const System::String_t System::Crypto::SetCustomKeyAddress() noexcept
{
    String_t key_address = "";
RecoveryKeySetPath:
    std::cout << "Location to Store Recovery Key (type '?' for default) : ";
    std::cin >> key_address;
    if (key_address.size() == 0 || key_address.size() > MAX_PATH_LENGTH) [[unlikely]]
    {
        std::cout << "Path Length error! [0/" << MAX_PATH_LENGTH << "]\n";
        goto RecoveryKeySetPath;
    }
    else if (key_address.compare("?") == 0) [[likely]]
    {
        key_address.clear();
        key_address = DEFAULT_SECURE_OWN_KEY_PATH;
    }

    return key_address;
};

[[maybe_unused, nodiscard]] const System::String_t System::Crypto::SetRecoveryKey() noexcept
{
    String_t recovery_key = "";
RecoveryKeySet:
    std::cout << "Recovery Key: ";
    std::cin >> recovery_key;
    if (recovery_key.size() < 6 || recovery_key.size() > 100) [[unlikely]]
    {
        std::cout << "Recovery key length error, [6/100]\n";
        goto RecoveryKeySet;
    }
    return recovery_key;
};

[[maybe_unused, nodiscard]] const System::String_t System::Crypto::SetTargetPath() noexcept
{
    String_t target_path = "";
TargetPathSupply:
    std::cout << "Target to Encrypt (type '.' for root) : ";
    std::cin >> target_path;
    if (target_path.empty()) [[unlikely]]
    {
        std::cout << "path is empty!\n";
        goto TargetPathSupply;
    }
    else if (target_path.compare(".") == 0) [[unlikely]]
    {
        target_path.clear();
        target_path = BASE_DIRECTORY;
    }
    else if (!DirectoryExists(target_path) && !FileExists(target_path)) [[unlikely]]
    {
        std::cout << "Supplied Path not found!\n";
        goto TargetPathSupply;
    }

    return target_path;
};

[[maybe_unused, nodiscard]] const bool System::Crypto::Want2CreateBackup() noexcept
{
    std::cout << "Create Backup? [y/n] : ";
    char x;
    std::cin >> x;
    if (x == 'y' || x == 'Y') [[likely]]
    {
        return true;
    }
    return false;
};

[[maybe_unused, nodiscard]] const bool System::Crypto::Approve() noexcept
{
    Char_t x;
    std::cout << "Continue? [y/n]: ";
    std::cin >> x;
    return (bool)(x == 'y' || x == 'Y');
}

/*                               Key/Iv/Secrects                             *\
\*****************************************************************************/

[[maybe_unused, nodiscard]] const System::RecoveryMode System::Crypto::GetRecoveryMode()
{
    if (RegistryPathExists()) [[likely]]
    {
        if (FileExists(RECOVERY_MODE_PATH)) [[likely]]
        {
            const String_t rMode = ReadFile(RECOVERY_MODE_PATH).c_str();
            if (rMode.size() > 0 && rMode.size() < 5) [[likely]]
                return rMode.compare("G") == 0 || rMode.compare("S") == 0 ? (rMode.compare("G") == 0 ? RecoveryMode::GENERATE_SECURE : RecoveryMode::CUSTOM_SUPPLY) : RecoveryMode::NONE;
        }
    }
    return RecoveryMode::NONE;
};

[[maybe_unused, nodiscard]] const System::String_t System::Crypto::GetRecoveryKeyAddress()
{
    String_t kAddress;
    if (FileExists(SECURE_OWN_KEY_REF)) [[likely]]
    {
        kAddress = ReadFile(SECURE_OWN_KEY_REF).c_str();
    }
    return kAddress;
};

/**
 * Parse generated secure key block with *raw_key* content, and store it into file.
 * @param const StringView_t&
 * @returns void
 */
[[maybe_unused]] void System::Crypto::RecoveryKeyIntersectAndRegister(const StringView_t &raw_key)
{
    if (raw_key.empty()) [[unlikely]]
    {
        throw std::runtime_error("Raw key is empty!");
    }

    String_t rkey = raw_key.data();
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, key.size(), (CryptoPP::byte *)rkey.data(), rkey.size());
    const String_t location_drop = GetRecoveryKeyAddress();
    if (!location_drop.empty()) [[likely]]
    {
        std::ofstream StoreKey(location_drop.data(), std::ios::binary);
        if (StoreKey.is_open()) [[likely]]
        {
            StoreKey.write(reinterpret_cast<const char *>(key.data()), key.SizeInBytes());
        }
        StoreKey.close();
    }
};

/**
 * Parse generated secure key block with *raw_key* content, and return result key block.
 * @param const StringView_t&
 * @returns std::optional<CryptoPP::SecByteBlock>
 */
[[maybe_unused]] std::optional<CryptoPP::SecByteBlock> System::Crypto::RecoveryKeyIntersect(const StringView_t &raw_key)
{
    std::optional<CryptoPP::SecByteBlock> key_parse = std::nullopt;
    try
    {
        if (raw_key.empty()) [[unlikely]]
            throw std::runtime_error("Supplied Raw key empty!");

        String_t rkey = raw_key.data();
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
        pbkdf2.DeriveKey(key, key.size(), (CryptoPP::byte *)rkey.data(), rkey.size());
        key_parse = key;
    }
    catch (const std::runtime_error &_e)
    {
        std::cerr << "Custom Key Parse Error: " << _e.what() << '\n';
    }
    catch (const std::exception &_e)
    {
        std::cerr << "Custom Key Parse Exception: " << _e.what() << '\n';
    }
    return key_parse;
};

[[maybe_unused, nodiscard]] const std::optional<CryptoPP::SecByteBlock> System::Crypto::GetRecoveryKey()
{
    std::optional<CryptoPP::SecByteBlock> yVal;
    if (FileExists(SECURE_OWN_KEY_REF)) [[likely]]
    {
        const String_t get_key_location = ReadFile(SECURE_OWN_KEY_REF);
        if (get_key_location.empty()) [[unlikely]]
        {
            throw std::runtime_error("Cannot Find Custom Key Location!");
        }
        std::ifstream ReadKeyFromFile(get_key_location.c_str(), std::ios::binary);
        if (ReadKeyFromFile.is_open()) [[likely]]
        {
            ReadKeyFromFile.seekg(0, std::ios::end);
            yVal = CryptoPP::SecByteBlock(ReadKeyFromFile.tellg());
            ReadKeyFromFile.seekg(0, std::ios::beg);
            ReadKeyFromFile.read(reinterpret_cast<char *>(yVal.value().BytePtr()), yVal.value().size());
            ReadKeyFromFile.close();
        }
    }
    return yVal;
};

[[maybe_unused]] void System::Crypto::RegisterTargetPath(const StringView_t &target)
{
    if (target.empty()) [[unlikely]]
        return;

    if (!RegistryPathExists()) [[likely]]
    {
        if (!RegistryPathCreate()) [[unlikely]]
        {
            throw std::runtime_error("Cannot create Registry Address!");
        }
    }

    WriteFile(TARGET_ADDRESS_PATH, target, WriteFileMode::CREATE_NEW);
    const String_t get_target = ReadFile(TARGET_ADDRESS_PATH);
    if (get_target.empty() || get_target.compare(" ") == 0) [[unlikely]]
    {
        throw std::runtime_error("Cannot get target file name, maybe empty or not valid!");
    }
};

[[nodiscard]] const std::optional<System::String_t> System::Crypto::GetTargetPath()
{
    std::optional<String_t> rOptBlock = std::nullopt;
    if (FileExists(TARGET_ADDRESS_PATH)) [[likely]]
    {
        const String_t target_path = ReadFile(TARGET_ADDRESS_PATH).c_str();
        if (!target_path.empty()) [[likely]]
        {
            rOptBlock = std::move(target_path.data());
        }
    }
    return rOptBlock;
};

/**
 * Verify if key is stored, and stored key size verification to prevent illformed keys from being used, returns true if key is found and valid, false otherwise.
 * @param void
 * @returns const bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::IsKeySet()
{
    try
    {
        if (FileExists(SECURE_OWN_KEY_REF)) [[likely]]
        {
            const String_t key_validate = ReadFile(std::move(ReadFile(SECURE_OWN_KEY_REF).c_str()));
            if (!key_validate.empty()) [[likely]]
            {
                LogMessage("KEY SIZE: ", key_validate.size(), '\n');
                if (key_validate.size() == CryptoPP::AES::DEFAULT_KEYLENGTH) [[likely]]
                {
                    return true;
                }
            }
        }
    }
    catch (const std::exception &_e)
    {
        return false;
    }
    return false;
};

/*                               Compression                                 *\
\*****************************************************************************/

/**
 * Compress file
 * @param const StringView_t&
 * @param const StringView_t&
 * @returns void
 */
[[maybe_unused]] void System::Crypto::CompressFile(const StringView_t &file_path, const StringView_t &dest_file)
{
    try
    {
        std::ifstream readFileContent(file_path.data(), std::ios::binary);
        std::ofstream writeFileContent(dest_file.data(), std::ios::binary);
        if (!readFileContent.is_open() || !writeFileContent.is_open())
        {
            throw std::runtime_error("Cannot read or write to file!");
        }

        z_stream deflateStream;
        deflateStream.zalloc = Z_NULL;
        deflateStream.zfree = Z_NULL;
        deflateStream.opaque = Z_NULL;

        if (deflateInit(&deflateStream, Z_BEST_COMPRESSION) != Z_OK)
        {
            throw std::runtime_error("Failed to initialize zlib for compression.");
        }

        char inBuffer[16384];
        char outBuffer[16384];

        int bytesRead = 0;
        do
        {
            readFileContent.read(inBuffer, sizeof(inBuffer));
            bytesRead = static_cast<int>(readFileContent.gcount());
            if (bytesRead > 0)
            {
                deflateStream.avail_in = bytesRead;
                deflateStream.next_in = reinterpret_cast<Bytef *>(inBuffer);

                do
                {
                    deflateStream.avail_out = sizeof(outBuffer);
                    deflateStream.next_out = reinterpret_cast<Bytef *>(outBuffer);
                    deflate(&deflateStream, Z_NO_FLUSH);
                    int compressedBytes = sizeof(outBuffer) - deflateStream.avail_out;
                    writeFileContent.write(outBuffer, compressedBytes);
                } while (deflateStream.avail_out == 0);
            }
        } while (bytesRead > 0);

        do
        {
            deflateStream.avail_out = sizeof(outBuffer);
            deflateStream.next_out = reinterpret_cast<Bytef *>(outBuffer);
            int result = deflate(&deflateStream, Z_FINISH);
            int compressedBytes = sizeof(outBuffer) - deflateStream.avail_out;
            writeFileContent.write(outBuffer, compressedBytes);
            if (result == Z_STREAM_END)
            {
                break;
            }
        } while (true);

        deflateEnd(&deflateStream);
        readFileContent.close();
        writeFileContent.close();
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "Deflate Error: " << e.what() << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Deflate Exception: " << e.what() << std::endl;
    }
};

/**
 * Decompress file
 * @param const StringView_t&
 * @param const StringView_t&
 * @returns void
 */
[[maybe_unused]] void System::Crypto::DecompressFile(const StringView_t &compressedFile, const StringView_t &decompressedFile)
{
    std::ifstream inFile(compressedFile.data(), std::ios::binary);
    if (!inFile.is_open())
    {
        LogError("Error: Failed to open input file.\n");
        return;
    }

    std::ofstream outFile(decompressedFile.data(), std::ios::binary);
    if (!outFile.is_open())
    {
        LogError("Error: Failed to open output file.\n");
        inFile.close();
        return;
    }

    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = 0;
    stream.next_in = Z_NULL;

    if (inflateInit(&stream) != Z_OK)
    {
        LogError("Error: Failed to initialize zlib for decompression.\n");
        inFile.close();
        outFile.close();
        return;
    }

    char inBuffer[16384];
    char outBuffer[16384];

    int bytesRead = 0;
    do
    {
        inFile.read(inBuffer, sizeof(inBuffer));
        bytesRead = static_cast<int>(inFile.gcount());
        if (bytesRead > 0)
        {
            stream.avail_in = bytesRead;
            stream.next_in = reinterpret_cast<Bytef *>(inBuffer);

            do
            {
                stream.avail_out = sizeof(outBuffer);
                stream.next_out = reinterpret_cast<Bytef *>(outBuffer);
                int result = inflate(&stream, Z_NO_FLUSH);
                int decompressedBytes = sizeof(outBuffer) - stream.avail_out;
                outFile.write(outBuffer, decompressedBytes);
                if (result == Z_STREAM_END)
                {
                    break;
                }
            } while (stream.avail_out == 0);
        }
    } while (bytesRead > 0);

    inflateEnd(&stream);

    inFile.close();
    outFile.close();
};

/*                    SSL Asymmetric/Symmetric Encryption                    *\
\*****************************************************************************/

/**
 * Generate Ssl public/private keys, returns true if keys are created, false otherwise.
 * @param const StringView_t& private key path
 * @param const StringView_t& public key path
 * @param const UInt16_t the key size to generate
 * @returns const bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::GenSslKeyPair(const StringView_t &private_key_path, const StringView_t &public_key_path, const UInt16_t key_size = 2048)
{
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, key_size);

    try
    {
        Base64Encoder base64Encoder(new FileSink(private_key_path.data()));
        privateKey.Save(base64Encoder);
        base64Encoder.MessageEnd();

        LogMessage("Private key saved to: ", private_key_path, '\n');
    }
    catch (const Exception &ex)
    {
        std::cerr << "Failed to save private key: " << ex.what() << std::endl;
        return false;
    }

    RSA::PublicKey publicKey(privateKey);
    try
    {
        Base64Encoder base64Encoder(new FileSink(public_key_path.data()));
        publicKey.Save(base64Encoder);
        base64Encoder.MessageEnd();

        LogMessage("Public key saved to: ", std::move(public_key_path), '\n');
        return true;
    }
    catch (const Exception &ex)
    {
        std::cerr << "Failed to save public key: " << ex.what() << std::endl;
        return false;
    }
    return true;
};

/**
 * Generate a pair of ssl public/private keys, returns true if keys are created, false otherwise.
 * @param const System::SslKeyBlock, block containing private/public key and key size
 * @returns const bool
 */
[[maybe_unused, nodiscard]] const bool System::Crypto::GenSslKeyPair(const System::SslKeyBlock key_info)
{
    if (key_info.public_key.size() < 1 || key_info.private_key.size() < 1)
    {
        std::cout << "Ssl Public/Private key paths not supplied, please use flags --public=/path/to/public/key --private=/path/to/private/key --keysize=2048\n";
        return false;
    }
    using namespace CryptoPP;
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, key_info.key_size);

    try
    {
        Base64Encoder base64Encoder(new FileSink(key_info.private_key.c_str()));
        privateKey.Save(base64Encoder);
        base64Encoder.MessageEnd();

        LogMessage("Private key saved to: ", key_info.private_key.c_str(), '\n');
    }
    catch (const Exception &ex)
    {
        std::cerr << "Failed to save private key: " << ex.what() << std::endl;
        return false;
    }

    RSA::PublicKey publicKey(privateKey);
    try
    {
        Base64Encoder base64Encoder(new FileSink(key_info.public_key.c_str()));
        publicKey.Save(base64Encoder);
        base64Encoder.MessageEnd();

        LogMessage("Public key saved to: ", key_info.public_key.c_str(), '\n');
        return true;
    }
    catch (const Exception &ex)
    {
        std::cerr << "Failed to save public key: " << ex.what() << std::endl;
        return false;
    }
    return true;
};

/*                               Misc Operators                              *\
\*****************************************************************************/

/**
 * Sleep if exeMode has proper state on(EASED)
 * @param const Int32_t value ot sleep for in microseconds, 1000000 = 1 second, 2 seconds = 2000000
 * @returns void
 */
[[maybe_unused]] void System::Crypto::CondWait(const Int32_t _wtime) noexcept
{
    if (exeMode & ExecuteMode::EASED) [[likely]]
        std::this_thread::sleep_for(std::chrono::microseconds(_wtime));
};

/**
 * Use CLI args to set exe mode.
 * @param const int
 * @param char**
 * @returns void
 */
[[maybe_unused]] void System::Crypto::CliSetExeMode(const int argc, char **argv)
{
    try
    {
        if (argc > 1) [[unlikely]]
        {
            for (UInt16_t _j{0}; _j < argc; ++_j)
            {
                if (StringView_t(argv[_j]).compare("--backup") == 0)
                    *with_backup = 1;
                else if (StringView_t(argv[_j]).compare("--atomic") == 0)
                    exeMode ^= ExecuteMode::EASED;
                else if (StringView_t(argv[_j]).compare("--silent") == 0)
                    exeMode ^= ExecuteMode::VERBOSE;
            }
        }
    }
    catch (const std::exception &_e)
    {
        LogWarning("Error: Cannot retrieve argument list -> ", std::move(_e.what()));
    }
};

[[maybe_unused, nodiscard]] const System::SslKeyBlock System::Crypto::CliSslFlagCollect(const int argc, char **argv)
{
    SslKeyBlock _k{.private_key{}, .public_key{}, .key_size{DEFAULT_SSL_KEY_SIZE}};
    try
    {
        if (argc > 1) [[likely]]
        {
            for (UInt16_t _j{0}; _j < argc; ++_j)
            {
                String_t _f = String_t(argv[_j]);
    
                if (_f.find("--private=") != std::string::npos)
                {
                    _k.private_key = _f.substr(_f.find("=")+1);
                }
                else if (_f.find("--public=") != std::string::npos)
                {
                    _k.public_key = _f.substr(_f.find("=")+1);
                }
                else if (_f.find("--keysize") != std::string::npos)
                {
                    _k.key_size = atoi(_f.substr(_f.find("=")+1).c_str());
                }
            }
        }
    }
    catch (const std::exception &_e)
    {
        LogWarning("Error: Cannot retrieve argument list -> ", std::move(_e.what()));
    }
    std::cout << "Ssl Public Key Path: " << _k.public_key << '\n';
    std::cout << "Ssl Private Key Path: " << _k.private_key << '\n';
    std::cout << "Ssl Key Size: " << _k.key_size << '\n';
    return _k;
};

/*                        Private Member Functions                           *\
\*****************************************************************************/

/**
 * Generate a random Pseudo number
 * @param void
 * @returns UInt32_t
 */
const System::UInt32_t System::Crypto::__GenRandomNumber(void)
{
    std::random_device seeder;
    std::mt19937 generate(seeder());
    std::uniform_int_distribution<UInt32_t> create_bytes((UInt32_t)9999999, (UInt32_t)99999999999999);
    return create_bytes(generate);
};

[[maybe_unused, nodiscard]] const System::PathBlocks System::Crypto::__SplitPath(const System::StringView_t &target)
{
    PathBlocks PathFrame{.path{target.data()}, .file{target.data()}};
    try
    {
        if (!target.empty()) [[likely]]
        {
            const System::StringView_t _pslice = target.data();

            if (_pslice.find(PATH_SEPARATOR) != std::string::npos) [[likely]]
            {
                PathFrame.file = _pslice.substr(_pslice.find_last_of(PATH_SEPARATOR) + 1, _pslice.size() - 1);
                PathFrame.path = _pslice.substr(0, _pslice.find_last_of(PATH_SEPARATOR) + 1);
            }
        }
    }
    catch (const std::exception &_e)
    {
        LogWarning("Split Path Error: ", _e.what(), '\n');
    }
    return PathFrame;
};

void System::Crypto::__ByteShiftBlocks(const System::StringView_t &file_name, System::String_t &new_file_name, const bool _plus)
{
    if (file_name.empty())
        return;

    for (const char _char : file_name)
        new_file_name += static_cast<System::Char_t>(_plus ? (static_cast<System::UInt16_t>(_char) + 3) : static_cast<System::UInt16_t>(_char) - 3);
};

#endif

#endif

#endif