#pragma once

#include <vector>

#include "asmjit/asmjit.h"
#ifdef __aarch64__
    #include "asmjit/a64.h"
#else
    #include "asmjit/a32.h"
#endif

struct MethodInfo;

class Patcher
{
  public:
    Patcher(MethodInfo *method);

    asmjit::Error ret();
    asmjit::Error movInt16(int16_t value);
    asmjit::Error movUInt16(uint16_t value);

    asmjit::Error movInt32(int32_t value);
    asmjit::Error movUInt32(uint32_t value);

    // FIXME: currently handled like 32 bit number so it wouldn't work on 64 bit number
    asmjit::Error movInt64(int64_t value);
    asmjit::Error movUInt64(uint64_t value);

    asmjit::Error movFloat(float value);

    asmjit::Error movBool(bool value);

    asmjit::Error movPtr(void *value);

    std::vector<uint8_t> patch();
    std::vector<uint8_t> getCode();

  private:
    asmjit::CodeHolder code;
#ifdef __aarch64__
    asmjit::a64::Assembler assembler;
#else
    asmjit::a32::Assembler assembler;
#endif
    void *target;
};
