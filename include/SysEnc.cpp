#pragma once

// header guarding
#ifndef __SYSTEM_ENCRYPTION_FF__
#include "SysEnc.hpp"
 
// double check for namespace macro definition validation
#if defined(__SYSTEM_ENCRYPTION_FF__)

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
[[maybe_unused, nodiscard]] const System::String_t System::Crypto::CreateTestDirectory(const StringView_t &dir_path, const std::initializer_list<String_t> test_files) {
    String_t rVal;
    if (dir_path.empty())
    {
        LogWarning("Test Directory is empty!\n");
        return rVal;
    }
    if(test_files.size() == 0){
        LogWarning("File list is empty, no files will be created..\n");
    }
    if(DirectoryExists(dir_path)){
        LogWarning("Directory already exists!\n");
        return rVal;
    }
    std::filesystem::create_directories(std::move(dir_path.data())) || std::filesystem::create_directory(std::move(dir_path.data()));
    if(DirectoryExists(dir_path.data())){
        for(const String_t &new_file: test_files){
            if(new_file.compare(".") == 0 || new_file.compare("..") == 0)
                continue;

            String_t entry_id = dir_path.data();
            entry_id += PATH_SEPARATOR;
            entry_id += std::move(new_file.c_str());
            LogMessage("Creating test file <", entry_id, ">...\n");
            std::ofstream createFile(entry_id.c_str());
            createFile << "Something in this file";
            createFile.close();
            if(FileExists(std::move(entry_id.c_str()))){
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
    std::cout<<"Select One [1/2] : ";
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
