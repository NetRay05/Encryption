# System Encryption Utility

---------------------------

[Encryption](https://en.wikipedia.org/wiki/Encryption) utility written in c++

## User Notice:
contact address: **auc_02@proton.me**

you better backup first.
The Encryption use [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) (Cipher Block Chaining) and [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (Advanced Encryption Standard) algorithms to guarantee maximum security degree and data integrity. user supplied location where to store  Block **Key** and [IV(Initialization-Vector)](https://en.wikipedia.org/wiki/Initialization_vector) and path to encrypt/decrypt.
you will be prompted to confirm your actions before actually proceeding with execution.

**Decryption**
For decryption process, key/IV block locations will removed from system.
statically **pre-compiled**, both for encryption(enc.cpp = enc/enc.exe) and decryption(dec.cpp = dec/dec.exe). This was compiled on Linux **x86-64** bit.
Heavyly relying on **crypto++**, and for file streaming operations it uses **std::filesystem** and std::[i/o]fstream.


## Table Of Contents
------------------------------------------------------------------------------------------

* Usage
* Risk Assessment
* OS/Architecture Support
* GPG Version
* Pseudo-Code

### NOTICE
.gpg files decryption Passphrase is: **0987654321QWERTYqwerty** 

## Usage
EncryptFile/DecryptFile anything from a simple .txt file, to everything else which is not a regular text file(binary file). 
Create a **backup** copy of your data, just in case!
There is no UI(User-Interface), so you might need to have some basic experience with **CLI**.

**Setting CLI Flags**

Set Execution Verbosity and Atomicity Flags, `./enc -verbose=true` or `./enc -verbose=false` for omitting logs, if you want to perform an atomic operation instead of applying a small delay  during resource aggregation, `./enc -atomic=true` or `./enc -atomic=false` making the execution ETA slower but guaranteeing data integrity at higher rate of success and lower rate of failure(`./enc -atomic=true`). flags are optional, and the sequence order does not matter.

---------------------------------------------

Perform with atomicity and verbosity, no delay applied, will execute faster.

> ./enc -atomic=true -verbose=true

> ./dec -atomic=true -verbose=true

Perform with delay and no verbosity, will execute slower but increase success rate.

> ./enc -verbose=false -atomic=false

> ./dec -verbose=false -atomic=false

---------------------------------------------
 
## Risk Assessment
Some of the risks are obviously data corruption during runtime encryption/decryption, even if the success rate is almost 100%, you should create a backup copy of the data you want to encrypt before actually encrypting it.

## OS/Architecture Support
It is supported on most used Operating Systems such as **Linux**, **Windows**, **Mac** OS, supporting both **x86-64**, **x64** and **x86/32** bit System Architectures.


## GPG Version

**GPG Installation and Configuration**

----------------------------------------------

If you don't have gpg installed on your System, this is how you can install it:

> sudo apt-get install gnupg

If you haven't created your own pair or gpg public/private keys yet:

> gpg --full-generate-key

More about [GPG](https://www.redhat.com/sysadmin/encryption-decryption-gpg)

**TAR Installation**
Tar is a command line utility, so you should already have it installed by default, if you don't have tar installed on your system for some reason:

> sudo apt-get install tar

More about [Tar](https://man7.org/linux/man-pages/man1/tar.1.html)

There is a gpg(( encrypted version using **symmetric** encryption mode with **AES256** Key Block Size, it is just the same as the raw version, but provides more **confidentiality** and **integrity**, using the .gpg content is **preferable**, here's how you can decrypt the gpg version.

------------------------
**Navigate to the path of the downloaded .gpg file:**
> cd /path/to/gpg-file

------------------------
**DecryptFile the gpg_dblock.tar.gpg file:**
> gpg -d gpg_ublock.tar.gpg > real-content.tar

Supply the password provided above and wait for the execution, a real-content.tar will be created in the same directory, this is the tar file containing the data.

------------------------
**Extract from Tar, assuming you extracted into "real-content.tar", otherwise provide the .tar filename you have used.**
> tar -xvf real-content.tar

-------------------------
**Now You have SysEnc-v03 in the same directory, this is the result :), congrats!**


## Pseudo Code

### Public Methods

```cpp
    explicit Crypto();

[[nodiscard]] inline const uBlock<void *> Init(const InitMode_e __init_mode, const Int16_t __exe_mode);
    [[maybe_unused, nodiscard]] inline static const uBlock<KeyIvBlockPairPath> SupplyKeyIvPath(void);
    [[maybe_unused, nodiscard]] inline static const String_t SupplyTargetPath(void);
    [[maybe_unused, nodiscard]] inline static const uBlock<KeyIvBlockPairPath> StoreKeyIvAddress(const KeyIvBlockPairPath &_key_iv_location);
    [[nodiscard]] inline static const uBlock<KeyIvBlockPairPath> GetKeyIvAddress(void);
    [[nodiscard]] inline static const uBlock<KeyIvBlockPairPath> KisbUseLocation(const KeyIvBlockPairPath &__kisb_location);
    [[maybe_unused, nodiscard]] inline static const uBlock<KeyIvBlock> GenerateKeyIv(void);
    [[nodiscard]] inline static const uBlock<KeyIvBlockInfo> IntersectSecBlocks(const KeyIvBlock &__kisb_block, const KeyIvBlockPairPath &__kisb_path);
    [[nodiscard]] inline static const uBlock<KeyIvBlock> KisbCollect(const KeyIvBlockPairPath &__kisb_path);
    [[nodiscard]] inline static const uBlock<KeyIvBlock> KisbCollect(void);
    [[nodiscard]] inline const bool KisbDelegate(const KeyIvBlockInfo &__kisb_block);
    [[maybe_unused, nodiscard]] inline const ErrorBlockInfo EncryptFile(const String_t &__file_name) __attribute__((hot));
    [[maybe_unused, nodiscard]] inline const ErrorBlockInfo DecryptFile(const String_t &__file_name) __attribute__((hot));

    [[nodiscard]] inline static const bool Rename(const StringView_t &__file_name, const SourceRenameMode_e __rename_mode) __attribute__((hot));
    [[maybe_unused]] inline void SetRootDirectory(const StringView_t &__root) noexcept;
    [[maybe_unused, nodiscard]] inline static uBlock<String_t> RegisterTargetDirectory(const StringView_t &__target);
    [[maybe_unused, nodiscard]] inline static uBlock<String_t> RetrieveTargetDirectory(void);
    [[nodiscard]] inline static const uBlock<std::vector<String_t>> ResourceAggregate(const StringView_t &__use_root);
    [[maybe_unused, nodiscard]] inline const String_t *GetRoot(void) noexcept;
    [[maybe_unused, nodiscard]] inline static const bool DirectoryExists(const StringView_t &__dir) noexcept __attribute__((hot));
    [[maybe_unused]] inline void CleanOperation(void);
    [[maybe_unused]] inline static void LogMessage() __attribute__((hot, nothrow));
    template <typename mT, typename... tArgs> [[maybe_unused]] inline static void LogMessage(mT msg, tArgs... __mlist) __attribute__((hot, nothrow));
    [[maybe_unused]] inline static void LogWarning() __attribute__((hot, nothrow));
    template <typename mT, typename... tArgs> [[maybe_unused]] inline static void LogWarning(mT msg, tArgs... __mlist) __attribute__((hot, nothrow));
    [[maybe_unused]] inline static void LogError() __attribute__((hot, nothrow));
    template <typename mT, typename... tArgs> [[maybe_unused]] inline static void LogError(mT msg, tArgs... __mlist) __attribute__((hot, nothrow));
    [[maybe_unused]] inline static void CondWait(const Int32_t _wtime) noexcept;
    [[maybe_unused]] inline void UseCommandLineArguments(const int argc, char **argv);
    [[maybe_unused]] inline static const bool BackupTarget(const StringView_t &__dir_name);

    ~Crypto();
```

### PRIVATE METHODS
```cpp
    template <typename ET> inline static void __ErrorFrameInjection(const ET &_e, ErrorBlockInfo &_eBlock) noexcept __attribute__((hot));
    [[maybe_unused, nodiscard]] inline static const uBlock<void *> __CreateDefaultKisbReference(void);
    [[maybe_unused, nodiscard]] inline static const bool __HasKisbAddressInfo(void);
    [[nodiscard]] inline static const SplitPathObj __SplitPath(const StringView_t &__path) __attribute__((hot));
    inline static void __AddPathToForbidden(const KeyIvBlockPairPath &__path) noexcept;
    [[nodiscard]] inline static const bool __IsResourceForbidden(const StringView_t &__resource) noexcept __attribute__((hot));

    inline static void __FileRenameParseByte(const System::StringView_t &__file_name, System::String_t &__new_file_name, const bool _plus) __attribute__((hot, nothrow));
};
```
