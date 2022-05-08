#pragma once

#include <algorithm>
#include <functional>
#include <execution>
#include <random>
#include "MD5.h"
#include "aes_tables.h"

namespace cipher {

    enum class mode { ecb, cbc, cfb, ofb };

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

        static byte_block generate_initialization_vector();
        static std::vector<byte_block> m_to_byte_blocks(const std::string_view& text, bool complete_last_block);
        static std::string m_to_text(const std::vector<byte_block>& byte_blocks, bool delete_last_block);

        std::vector<byte_block> m_encrypt_ecb(const std::vector<byte_block>& plain_byte_blocks) const;
        std::vector<byte_block> m_decrypt_ecb(const std::vector<byte_block>& cipher_byte_blocks) const;

        std::vector<byte_block> m_encrypt_cbc(const std::vector<byte_block>& plain_byte_blocks) const;
        std::vector<byte_block> m_decrypt_cbc(const std::vector<byte_block>& cipher_byte_blocks) const;

        std::vector<byte_block> m_encrypt_cfb(const std::vector<byte_block>& plain_byte_blocks) const;
        std::vector<byte_block> m_decrypt_cfb(const std::vector<byte_block>& cipher_byte_blocks) const;

        std::vector<byte_block> m_encrypt_ofb(const std::vector<byte_block>& plain_byte_blocks) const;
        std::vector<byte_block> m_decrypt_ofb(const std::vector<byte_block>& cipher_byte_blocks) const;

    public:
        explicit aes128(const std::string_view& key);

        std::string encrypt(const std::string_view& plain_text, mode cipher_mode = mode::ecb) const;
        std::string decrypt(const std::string_view& cipher_text, mode cipher_mode = mode::ecb) const;
    };

}
