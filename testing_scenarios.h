#pragma once

#include "aes128.h"

std::string xor_strings(const std::string_view& lhs, const std::string_view& rhs);
std::string random_string(std::size_t size);

std::string generate_heavy_or_little_weight_string_block(int start_elem);