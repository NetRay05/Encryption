/******************************************************************************

    Copyright 2024

    File: enc.cpp 

    Author: NetRay

    Date: May 1 2024

    Flags: --atomic | --silent | --backup

    Description: This is a utility tool used to encrypt/decrypt data.

******************************************************************************/

//#include "../include/SysEnc.cpp"
#include "../single_file_unit/SysEnc.hpp"
int main(int argc, char **argv)
{
#if defined(__SYSTEM_ENCRYPTION_FF__)
    using namespace System;

    // Instance Declaration
    Crypto Encryptor;

    *Crypto::with_backup = false;

    try
    {
        // prepare env variables(verbosity, atomicity, backup)
        Encryptor.CliSetExeMode(argc, argv);

        // Set Recovery key
        const String_t recovery_key = Crypto::SetRecoveryKey();
        if (recovery_key.empty()) [[unlikely]]
            throw std::runtime_error("No Recovery Key Supplied!");

        // Set the target to encrypt
        const String_t set_target = Crypto::SetTargetPath();

        if (set_target.empty()) [[unlikely]]
            throw std::runtime_error("Target path is empty!!");

        std::cout << "Scheduling path '" << set_target.c_str() << "' for Full Encryption...\n";

        if (!Crypto::Approve()) [[unlikely]]
        {
            std::cout << "Ok, aborting!\n";
            return EXIT_SUCCESS;
        }

        // register/store target
        Crypto::RegisterTargetPath(std::move(set_target));

        // get target
        const std::optional<String_t> use_target = Crypto::GetTargetPath();

        // verifying target value, if target was not registered, then stop
        if (!use_target.has_value()) [[unlikely]]
            throw std::runtime_error("no valid target path found!");

        std::cout << "Using Target Path: " << use_target.value() << std::endl;

        // Collect Resources
        const std::vector<String_t> aggregation_stack = Crypto::DirectoryAggregation(std::move(use_target.value()));

        if (aggregation_stack.empty()) [[unlikely]]
        {
            throw std::runtime_error("Nothing To Encrypt!");
        }

        // ask to create backup if no CLI arg for backup related was found
        if (*Crypto::with_backup == 0)
            *Crypto::with_backup = Crypto::Want2CreateBackup() ? 2 : 0;

        if (*Crypto::with_backup >= 1)
        {
            if (!Crypto::CreateBackup(std::move(use_target.value()))) [[unlikely]]
            {
                throw std::runtime_error("Backup Operation Failed.. aborting..");
            }
            std::cout << "Backup Create Successfully!\n";
        }

        // Prepare Secure Key Block
        const std::optional<CryptoPP::SecByteBlock> ParseKey = Crypto::RecoveryKeyIntersect(std::move(recovery_key));

        if (!ParseKey.has_value()) [[unlikely]]
            throw std::runtime_error("Error Intersection Recovery Key");

        // Encrypt File Content
        for (const String_t &resource : aggregation_stack)
            if (!Crypto::EncryptFile(std::move(resource.c_str()), ParseKey.value())) [[unlikely]]
                throw std::runtime_error("Cannot encrypt file");
    }
    catch (const std::runtime_error &_e)
    {
        Crypto::LogError("Error: ", _e.what(), '\n');
    }
    catch (const std::exception &_e)
    {
        Crypto::LogError("Error: ", _e.what(), '\n');
    }
#endif
    return EXIT_SUCCESS;
};
