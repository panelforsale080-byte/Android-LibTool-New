#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Il2CppDetector
{
    struct DetectedLibrary
    {
        std::string name;
        uint64_t baseAddress;
        uint64_t size;
        bool isIl2Cpp;
        std::string metadataLocation; // path or memory range
        std::string version; // Unity version if detected
    };

    // Scan a process for all loaded .so libraries
    std::vector<DetectedLibrary> scanProcessLibraries(int pid);

    // Check if a library at given path/address is an Il2Cpp library
    bool isIl2CppLibrary(const std::string &libraryPath, uint64_t baseAddress, uint64_t size);

    // Parse ELF header and extract information
    struct ElfInfo
    {
        uint64_t entry;
        uint64_t phoff;
        uint64_t shoff;
        uint32_t flags;
        uint16_t ehsize;
        uint16_t phentsize;
        uint16_t phnum;
        uint16_t shentsize;
        uint16_t shnum;
        uint16_t shstrndx;
    };

    // Read ELF header from memory
    bool readElfHeader(const void *memory, uint64_t size, ElfInfo &info);

    // Search for Il2Cpp signatures in ELF
    bool searchIl2CppSignatures(const void *memory, uint64_t size, std::string &metadataLocation, std::string &version);

    // Search for global-metadata.dat magic (0xFAB11BAF)
    bool findGlobalMetadata(const void *memory, uint64_t size, uint64_t &offset);

    // Search for Il2Cpp function symbols
    bool findIl2CppFunctions(const void *memory, uint64_t size);

    // Get Unity version from library
    std::string getUnityVersion(const void *memory, uint64_t size);
}