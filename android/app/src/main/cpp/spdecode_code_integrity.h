#pragma once
namespace spdecode {
enum class CodeIntegrity { Unknown, Match, Changed };
// Compare this DSO's read-only executable PT_LOAD bytes with its mapped file.
// ASLR is accounted for; writable/relocated data is deliberately excluded.
CodeIntegrity verifyOwnExecutable();
}
