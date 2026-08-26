#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct SoTraceExecRange
{
    uint64_t begin = 0;
    uint64_t end = 0;
};

struct SoTraceModule
{
    std::string name;
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
    std::vector<SoTraceExecRange> execRanges;
};

struct SoTraceHitEntry
{
    uint64_t offset = 0;
    std::string mnemonic;
    uint64_t hits = 0;
};

struct SoTraceState
{
    bool active = false;
    bool starting = false;
    bool hookInstalling = false;
    std::string status;
    std::string moduleName;
    uint64_t base = 0;
    size_t threadCount = 0;
    size_t insnSlots = 0;
    uint64_t totalExecutions = 0;
    uint64_t sampleHits = 0;
    uint64_t hookHits = 0;
    uint64_t sampleRounds = 0;
    size_t hookedCount = 0;
    size_t interceptorCount = 0;
    size_t dobbyCount = 0;
    size_t hookFailed = 0;
    size_t hookInstallDone = 0;
    size_t hookInstallTotal = 0;
    size_t hookCap = 0;
};

namespace SoMonitorTrace
{
    void Start(const SoTraceModule &module);
    void Stop();
    SoTraceState GetState();
    std::vector<SoTraceHitEntry> GetSnapshot(bool hideZeroHits, uint64_t minHits, bool sortByHitsDesc);
    void ClearHits();
    bool ExportCsv(const std::string &fileName, std::string &outPath);
    bool HookOffset(uint64_t offset, std::string &err);
}
