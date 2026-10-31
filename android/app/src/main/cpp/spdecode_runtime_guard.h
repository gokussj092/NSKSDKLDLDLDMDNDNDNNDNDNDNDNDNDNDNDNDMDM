#pragma once
#include <string>
namespace spdecode {
// Defense-in-depth signals only; not proof of an uncompromised device.
int runtimeRiskFromProc(const std::string& status,const std::string& maps);
int runtimeRisk();
}
