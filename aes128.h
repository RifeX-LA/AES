#pragma once

#include <algorithm>
#include <functional>
#include "MD5.h"
#include "aes_tables.h"

namespace cipher {

enum class mode {ecb, cbc, pcbc, cfb, ofb, ctr};

class aes128 {
    private:
        using byte_block = std::array<std::array<uint8_t, 4>, 4>;

        static constexpr std::size_t m_rounds = 10;
        std::array<byte_block, m_rounds + 1> m_key_schedule;

        static void m_sub_word(std::array<uint8_t, 4>& word);
        static void m_rot_word(std::array<uint8_t, 4>& word, std::ptrdiff_t offset);
        static uint8_t m_gmul(uint8_t a, uint8_t b);
        static void m_multiply_matrix_by_columns(byte_block& state, const byte_block& op_table);
        static void m_byte_block_transpose(byte_block& block);
        void m_key_expansion(const uint8_t* key);

        static void m_sub_bytes(byte_block& state);
        static void m_shift_rows(byte_block& state);
        static void m_mix_columns(byte_block& state);

        static void m_inv_sub_bytes(byte_block& state);
        static void m_inv_shift_rows(byte_block& state);
        static void m_inv_mix_columns(byte_block& state);

        static void m_xor_blocks(byte_block& lhs, const byte_block& rhs);

        void m_encrypt_block(byte_block& block) const;
        void m_decrypt_block(byte_block& block) const;

    public:
        explicit aes128(const std::string_view& key);

        std::string encrypt(const std::string_view& plain_text, mode cipher_mode = mode::ecb) const;
        std::string decrypt(const std::string_view& cipher_text, mode cipher_mode = mode::ecb) const;
};

}
