# System Encryption Utility

Encrypt anything from a single text/binary file to entire directories at once.
The utility class uses a CBC mode encryption along with AES standard to provide maximum confidentiality and security. Each encryption operation creates a new IV(Initialization-Vector) for additional security, encrypts the data using AES 256 key block size. The program work both as CLI execution as well as integrated library within any valid c++ codebase, for CLI mode you can supply additional flags to the operation. 

## Table Of Contents

* CLI Execution Flags
* Risk Assessment
* Class Member Function List
* Compiler & Platform
* Integrate(include)
* File Support
* Cryptography Algorithms
* C++ Pseudo Examples

## CLI Execution Flags
You can Supply various flags to directly instruct the operation on how to execute, some of these flags are:

* --atomic
* --silent
* --backup

### --atomic

> This flag will instruct the program to use `atomic` encryption executions, meaning `no delay` will be applied to each encryption execution, by dafaul, a delay of `5000` microseconds will be applied to each execution, by setting **--atomic** flag you will skip delay.

### --silent

> This flag will `disable verbose output`, omitting any printing operations to the console, by default program runs in verbose mode, there will be some console logging operations, messages like the encryption/decryption state, or files being operate on, and other types of messages, to prevent this behavior, set `--silent`

### --backup

> Create a backup copy of the target to encrypt before encryption, so in case of data loss there will be a copy of the data. By default no backup will be created, to create a backup copy of your data set `--backup` flag.

NOTE: the order of the flags does not matter.


## Risk Assessment
The risks you can run over are the tipical once you can encounter with any other encryption utility, that's why there is a special method for data backup, so you can mitigate the risk of losing data, data loss risk can be mitigated using `--backup` flag as instructed above.

## Class Member Functions

There are a few utility functions i would like to address here, there will be many i wont cover here, because they are not used directly from outside the class or not really usefull at all, the ones i wont to address are:

File Handlers

* WriteFile
* ReadFile
* FileExists
* DirectoryExists
* EncryptFile
* DecryptFile
* CreateBackup
* DirectoryAggregation

User Interaction

* SetRecoveryKey
* SetTargetPath
* CliSetExeMode

Encryption Related

* RecoveryKeyIntersect
* RegisterTargetPath
* GetTargetPath

## Compiler & Platform

In the `src` directory of the utility library, you will find a `compile.sh` shell script, a `enc`/`dec` pre-compiled executables, and `enc.cpp` and `dec.cpp` source file, the executables are compiled using `g++` compiler, statically compiling with `-lcryptopp` library, the executables will run on any system with or without `crypto++` library installed, the `compile.sh` shell script will compile the `enc.cpp` and `dec.cpp` into executables, which are already available as `enc` and `dec`, compiled using `-Os -Wall -Wno-deprecated -std=c++20 -lcryptopp -fsanitize=address` flags, yes, it was compiled using c++20 with `-std=c++20`, and with memory leak detection during runtime with `-fsanitize=address`, and other security/performace flags like `-0s` and `-Wall` for all warning. Compiled and Tested on `x86/64` Linux machine, so should work on most systems.


## Integration

You can integrete the utility class into your existing c++ code using `#include "SysEnc.cpp"` assuming your `SysEnc.cpp` source file is in the same directory subdivision from where is included(that would mean you extracted `SysEnc.cpp` from the `include directory` where it is located along with `SysEnc.hpp` and `header.hpp` which you should not do because `SysEnc.cpp` requires `SysEnc.hpp` and `SysEnc.hpp` requires `header.hpp`).
If for Example, if you `downloaded` the library in your `/home/you_user_name/Documents` Directory, then you must include it from `/home/user/Documents/SysEnc/include/SysEnc.cpp` as `SysEnc.cpp` is found within the `include` folder.


## File Support

The library will work for any type of file, text or binary, doesn't matter, any path/directory will be crypted, locked down by a secure private key, that only you must know, and then use this key for decryption, make sure you don't forget the key used with `./enc` execution, or data will be inacessible until you supply the right key  to the `dec` execution.
Examples of text files are: .txt, .csv, .log, .ini, .bat, .txt, .csv, .log, .conf, .sh, examples of binary files are: .exe, .jpg, .png, .mp3, .mp4 etc...


## Cryptography Algorithms

Here's how the process works in practice:

User-supplied Secret Key: The user provides a secret key, which acts as the basis for encryption and decryption.

Key Derivation: The provided secret key undergoes a key derivation process where it's combined with additional data (in this case, a 16-byte AES secret key) using a secure hash function (SHA256). This process ensures that the final encryption key is deterministic and derived from the user-supplied key.

Salt Generation: A salt, which is a random value, is generated to add entropy to the encryption process. This helps prevent the same input from generating the same output, enhancing security.

Encryption: The derived encryption key and the generated salt are used in combination with a secure encryption algorithm (AES in CBC mode) to encrypt the file content. CBC mode provides confidentiality by XORing each plaintext block with the previous ciphertext block before encryption.

Decryption: To decrypt the file, the same process is followed in reverse. The user-supplied secret key is used to derive the encryption key, which is then combined with the salt to decrypt the file content accurately.

The utility employs cryptographic algorithms such as AES and CBC mode encryption/decryption. Initially, a raw secret key provided by the user is utilized for decryption purposes. This key undergoes a transformation in an intersection function, where it is combined with a 16-byte AES secret key using the SHA256 hash function, resulting in the derivation of the final encryption key. Subsequently, this key is applied for file encryption. During this process, an additional 16-byte salt is generated, employing system entropy to produce pure pseudo-random values. CBC mode with AES encryption standard is then employed, combining the derived PKCS5_PBKDF2_HMAC cipher with the generated salt value for encryption. This ensures the encryption of the file content.


## C++ Examples

Note: Most of the member functions are `static`, so you don't need an instance of System::Crypto Object for most of the possible operations.

**Simple Instance**

```cpp
#include "/path/to/SysEnc.cpp"

using namespace System;

int main(int argc, char** argv){
Crypto Encryption; // crypto encryption instance
return 0;
}

```

Note: String_t is just a std::string alias!

---------------------------------------------------

Collect CLI arguments

> to collect CLI arguments(`--atomic`, `--silent`, `--backup`) and apply them to the Crypto class for encryption/decryption operations.
```cpp
Crypto::CliSetExeMode(argc, argv);
```


Prompt User for Secret Key

> the function prompts the user for a secret key, returns the user secret key.
```cpp
const String_t secret_key = Crypto::SetRecoveryKey();
```

Intersect Key

> the key must be intersected and derived from PKCS5_PBKDF2_HMAC before used for encryptionl, otherwise will lack securiry and/or not work.
```cpp
Crypto::RegisterTargetPath(); // this returns void
```


Set Target Path

> Set the target to encrypt/decrypt, path must be absolute not relative!

```cpp
const String_t target = Crypto::SetTargetPath(); // returns the target supplied
```


Register Target Path

> register target so for decryption there will be no need to supply this again, the target will be register within `/home/user/rkdata/._tgt0x0349343clrengtr7fg0923kjw.txt`.
```cpp
const std::optional<CryptoPP::SecByteBlock> key_intersection = Crypto::RecoveryKeyIntersect(); // return secure final key
```

Retrieve Target Path

> retrieve target registered with `Crypto::SetTargetPath()` function call.
```cpp
const String_t get_target = Crypto::GetTargetPath(); // return the target
```


Create Data Backup

> create a backup of target directory
```cpp
const bool backup_create = Crypto:::CreateBackup(); // returns true if backup created or false if failed to create
```

Aggregate Target Resources

> collect directory entries.
```cpp
const std::vector<String_t> aggregation = Crypto::DirectoryAggregate("/path/to/target_dir); // this will iterate over target_dir, collect and return its entries
```

Encrypt file

> encrypt text/binary file.
```cpp
const bool encrypted = Crypto::EncryptFile("/path/to/file.x");
```

Decrypt File
> decrypt encrypted text/binary file.
```cpp
const bool decrypted = Crypto::DecryptFile("/path/to/file");
```

Full `Encryption` Example, create a backup copy of `target` and encrypt it's content.
```cpp
#include "../include/SysEnc.cpp"

int main(int argc, char **argv)
{
   {
    using namespace System;
    Crypto Encryptor;

    *Crypto::with_backup = false; // set backup flag state to initial value(false)
    try
    {
        Encryptor.CliSetExeMode(argc, argv); // collect user flags if any

        const String_t recovery_key = Crypto::SetRecoveryKey(); // set recovery key

        if (recovery_key.empty()) [[unlikely]]
            throw std::runtime_error("No Recovery Key Supplied!");

        const String_t set_target = Crypto::SetTargetPath(); // set target path

        Crypto::RegisterTargetPath(set_target); // register/store target

        const std::vector<String_t> aggregation_stack = Crypto::DirectoryAggregation(use_target.value()); // collect entries

        // check if got any entries
        if (aggregation_stack.empty()) [[unlikely]]
            throw std::runtime_error("Nothing To Encrypt!");

        if (!Crypto::CreateBackup(use_target.value())) [[unlikely]]
            throw std::runtime_error("Backup Operation Failed.. aborting..");

        const std::optional<CryptoPP::SecByteBlock> ParseKey = Crypto::RecoveryKeyIntersect(recovery_key); // create/derive secure key from user key

        if (!ParseKey.has_value()) [[unlikely]] // check key
            throw std::runtime_error("Error Intersection Recovery Key");

        for (const String_t &resource : aggregation_stack) // aggregation iteration
            if (!Crypto::EncryptFile(std::move(resource.c_str()), ParseKey.value())) [[unlikely]] // encrypt entry and break loop if any error is encountered to prevent further damage
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
   }
    return EXIT_SUCCESS;
};

```


Full `Decryption` Example.
```cpp
#include "../include/SysEnc.cpp"

int main(int argc, char **argv)
{
   {
    using namespace System;
    Crypto Decryptor;

    try
    {
        const String_t recovery_key = Crypto::SetRecoveryKey(); // set recovery key

        if (recovery_key.empty()) [[unlikely]]
            throw std::runtime_error("No Recovery Key Supplied!");

        const String_t get_target = Crypto::GetTargetPath(); // get registered target path

        const std::vector<String_t> aggregation_stack = Crypto::DirectoryAggregation(get_target.value()); // collect entries

        // check if got any entries
        if (aggregation_stack.empty()) [[unlikely]]
            throw std::runtime_error("Nothing To Decrypt!");

        const std::optional<CryptoPP::SecByteBlock> ParseKey = Crypto::RecoveryKeyIntersect(recovery_key); // create/derive secure key from user key

        if (!ParseKey.has_value()) [[unlikely]] // check key
            throw std::runtime_error("Error Intersection Recovery Key");

        for (const String_t &resource : aggregation_stack) // aggregation iteration
            if (!Crypto::DecryptFile(std::move(resource.c_str()), ParseKey.value())) [[unlikely]] // decrypt entry and break loop if any error is encountered to prevent further damage
                throw std::runtime_error("Cannot decrypt file");
    }
    catch (const std::runtime_error &_e)
    {
        Crypto::LogError("Error: ", _e.what(), '\n');
    }
    catch (const std::exception &_e)
    {
        Crypto::LogError("Error: ", _e.what(), '\n');
    }
   }
    return EXIT_SUCCESS;
};

```

