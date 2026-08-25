#ifndef UTILS
#define UTILS

#include <jni.h>
#include <string>
#include "obfuscate.h"

#define targetLibName OBFUSCATE("libil2cpp.so") //Here you can change your target lib name.For example if you want to use this tool for MLBB (mobile legends bang bang) then change the lib name to "liblogic.so". However, I am not going to show that game in this vedio because it could receive a strike from Moonton. instead I will demonstrate it on my telegram channel.

//Ok now let's build it

typedef unsigned long DWORD;

DWORD findLibrary(const char *library);

DWORD getAbsoluteAddress(const char *libraryName, DWORD relativeAddr);

jboolean isGameLibLoaded(JNIEnv *env, jobject thiz);

bool isLibraryLoaded(const char *libraryName);

uintptr_t string2Offset(const char *c);

void patchOffsetSym(uintptr_t absolute_address, std::string hexBytes, bool isOn);

void patchOffset(const char *fileName, uint64_t offset, std::string hexBytes, bool isOn);

namespace ToastLength
{
    inline const int LENGTH_LONG = 1;
    inline const int LENGTH_SHORT = 0;
} // namespace ToastLength

#endif
