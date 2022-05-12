#pragma once

#include "aes128.h"

constexpr std::size_t bytes_in_megabyte = 1'048'576;

std::string xor_strings(const std::string_view& lhs, const std::string_view& rhs);
std::string random_string(std::size_t size);

std::string generate_heavy_or_little_weight_string_block(int start_elem);

std::string low_or_heavy_weight_plaintext_random_key(int start_elem);
std::string random_plaintext_low_or_heavy_weight_key(int start_elem);

std::string low_weight_plaintext_random_key();
std::string heavy_weight_plaintext_random_key();
std::string random_plaintext_low_weight_key();
std::string random_plaintext_heavy_weight_key();

std::string random_plain_text_and_key();
std::string random_plain_text_key_errors();
std::string plain_text_errors_random_key();

std::string plain_text_and_chipertext_correlation();
std::string block_chain_processing();
