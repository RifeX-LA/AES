#pragma once

#include "aes128.h"

std::string xor_strings(const std::string_view& lhs, const std::string_view& rhs);
std::string random_string(std::size_t size);

std::string generate_heavy_or_little_weight_string_block(int start_elem);

std::string low_weight_plaintext_random_key();
std::string heavy_weight_plaintext_random_key();
std::string random_plaintext_low_weight_key();
std::string random_plaintext_heavy_weight_key();