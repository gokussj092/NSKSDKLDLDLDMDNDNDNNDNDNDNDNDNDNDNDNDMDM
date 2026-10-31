#pragma once
#include <cstdint>
#include <string>
namespace spdecode {
enum RuntimeSignal : unsigned { Traced=1, InstrumentationModule=2, CodeChanged=4, JavaDebugger=8 };
enum RuntimeCheck : unsigned { StatusChecked=1, MapsChecked=2, CodeChecked=4, DebuggerChecked=8 };
struct RuntimeEvidence {
    unsigned signals=0;
    unsigned evaluated=0;
    std::uint64_t elapsedMicros=0;
    bool highRisk() const { return (signals & (Traced|CodeChanged|JavaDebugger))!=0; }
};
// Own-process evidence only; unavailable observations are UNKNOWN, never CLEAN.
RuntimeEvidence runtimeEvidenceFromProc(const std::string& status,const std::string& maps);
RuntimeEvidence runtimeEvidence();
std::string runtimeEvidenceJson(const RuntimeEvidence& evidence);
// Legacy bitmask does not assert successful evaluation.
int runtimeRiskFromProc(const std::string& status,const std::string& maps);
int runtimeRisk();
}
