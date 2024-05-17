#include "../include/SysEnc.cpp"

int main(int argc, char **argv)
{
#if defined(__SYSTEM_ENCRYPTION_FF__)
    using namespace System;

    // Instance Declaration
    Crypto Encryptor;

    *Crypto::with_backup = false;

    try
    {
        if(Crypto::GenSslKeyPair(Crypto::CliSslFlagCollect(argc, argv))){
            std::cout << "Ssl Keys Created!\n";
        }else{
            std::cout << "Ssl Keys Not Created!\n";
        }
        
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
