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
#include <sstream>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <unordered_set>
#include <thread>
#include <optional>
#include <sstream>

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

#endif
