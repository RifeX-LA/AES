#pragma once

#include <string>
#include <string_view>
#include "aes_tables.h"

namespace cipher {

enum class mode {ecb, cbc, pcbc, cfb, ofb, ctr};

class aes128 {
    private:
        using byte_block = std::array<std::array<uint8_t, 4>, 4>;

        std::array<byte_block, 11> m_key_schedule;

        constexpr void m_sub_bytes(byte_block& state) const;
        constexpr void m_shift_rows(byte_block& state) const;
        constexpr void m_mix_columns(byte_block& state) const;

        constexpr void m_inv_sub_bytes(byte_block& state) const;
        constexpr void m_inv_shift_rows(byte_block& state) const;
        constexpr void m_inv_mix_columns(byte_block& state) const;

        constexpr void m_key_expansion(const std::string_view& key);
        constexpr void m_add_round_key(byte_block& state) const;

        constexpr void m_encrypt_block(byte_block& block) const;
        constexpr void m_decrypt_block(byte_block& block) const;

    public:
        explicit constexpr aes128(const std::string_view& key);

        constexpr std::string encrypt(const std::string_view& plain_text, mode cipher_mode = mode::ecb) const;
        constexpr std::string decrypt(const std::string_view& cipher_text, mode cipher_mode = mode::ecb) const;
};

}
