/******************************************************************************

    Copyright 2024

    File: enc.cpp 

    Author: NetRay

    Date: May 1 2024

    Description: This is a utility tool used to encrypt/decrypt data.

******************************************************************************/

#include "../include/SysEnc.cpp"

int main(int argc, char **argv)
{
#if defined(__SYSTEM_ENCRYPTION_FF__)
    using namespace System;

    Crypto Decryptor;
    try
    {
        const String_t recovery_key = Crypto::SetRecoveryKey();

        const std::optional<CryptoPP::SecByteBlock> key_intersection = Crypto::RecoveryKeyIntersect(recovery_key);

        if (!key_intersection.has_value()) [[unlikely]]
            throw std::runtime_error("Error Parsing Recovery Key");

        std::optional<String_t> use_target = Crypto::GetTargetPath();

        std::cout << "Decrypting Target: " << use_target.value_or("unknown") << '\n';

        if (!use_target.has_value()) [[unlikely]]
        {
            use_target = Crypto::SetTargetPath();
            if (use_target.has_value()) [[unlikely]]
                throw std::runtime_error("Cannot state target path!");
            else if (!Crypto::FileExists(use_target.value()) && !Crypto::DirectoryExists(use_target.value()))
                throw std::runtime_error("Cannot find Target path!");
        }

        const std::vector<String_t> aggr_stack = Crypto::DirectoryAggregation(use_target.value());

        if (aggr_stack.empty()) [[unlikely]]
            throw std::runtime_error("Nothing to decrypt!");

        for (const String_t &entry : aggr_stack)
            if (!Crypto::DecryptFile(std::move(entry.c_str()), key_intersection.value())) [[unlikely]]
                throw std::runtime_error("Cannot Decrypt File!");
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
    return 0;
};
