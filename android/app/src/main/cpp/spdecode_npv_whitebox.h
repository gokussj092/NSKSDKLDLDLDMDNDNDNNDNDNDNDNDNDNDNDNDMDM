#pragma once
#include "spdecode_npv_crypto.h"
namespace spdecode::offline::npv {
Bytes modernBlock(const Bytes& input);
Bytes legacyBlock(const Bytes& input);
Bytes v1Block(const Bytes& input,bool alternate);
}
