#include "aes128.h"

void cipher::aes128::m_sub_word(std::array<uint8_t, 4>& word) {
    std::ranges::transform(word, word.begin(), [](uint8_t byte) {return aes::sbox[byte];});
}

void cipher::aes128::m_rot_word(std::array<uint8_t, 4>& word, std::ptrdiff_t i) {
    auto mid_iterator = (i >= 0) ? word.begin() : word.end();
    std::ranges::rotate(word, mid_iterator + i);
}

void cipher::aes128::m_byte_block_transpose(byte_block& block) {
    auto temp = block;
    for (std::size_t i = 0; i < block.size(); ++i) {
        for (std::size_t j = 0; j < block[i].size(); ++j) {
            block[i][j] = temp[j][i];
        }
    }
}

void cipher::aes128::m_key_expansion(const std::string_view& key) {
    for (std::size_t i = 0; i < m_key_schedule[0].size(); ++i) {
        for (std::size_t j = 0; j < m_key_schedule[0][i].size(); ++j) {
            m_key_schedule[0][i][j] = key[m_key_schedule[0].size() * i + j];
        }
    }

    for (std::size_t i = 1; i < m_key_schedule.size(); ++i) {
        for (std::size_t j = 0; j < m_key_schedule[i].size(); ++j) {
            auto temp = (j == 0) ? m_key_schedule[i - 1].back() : m_key_schedule[i][j - 1];
            if (j == 0) {
                m_rot_word(temp, 1);
                m_sub_word(temp);
                temp[0] ^= aes::rcon[i - 1];
            }
            std::ranges::transform(m_key_schedule[i - 1][j], temp, m_key_schedule[i][j].begin(), std::bit_xor<>());
        }
    }

    std::ranges::for_each(m_key_schedule, m_byte_block_transpose);
}

void cipher::aes128::m_sub_bytes(byte_block& state) {
    for (auto& row : state) {
        m_sub_word(row);
    }
}

void cipher::aes128::m_shift_rows(byte_block& state) {
    for (std::ptrdiff_t i = 1; i < state.size(); ++i) {
        m_rot_word(state[i], i);
    }
}

void cipher::aes128::m_mix_columns(cipher::aes128::byte_block &state) {
    // Will be implemented by Maxim
}

void cipher::aes128::m_inv_sub_bytes(byte_block& state) {
    for (auto& row : state) {
        std::ranges::transform(row, row.begin(), [](uint8_t byte) {return aes::inv_sbox[byte];});
    }
}

void cipher::aes128::m_inv_shift_rows(byte_block& state) {
    for (std::ptrdiff_t i = 1; i < state.size(); ++i) {
        m_rot_word(state[i], -i);
    }
}

void cipher::aes128::m_inv_mix_columns(cipher::aes128::byte_block &state) {
    // Will be implemented by Maxim
}

void cipher::aes128::m_xor_blocks(byte_block& lhs, const byte_block& rhs) {
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        std::ranges::transform(lhs[i], rhs[i], lhs[i].begin(), std::bit_xor<>());
    }
}

void cipher::aes128::m_encrypt_block(byte_block& block) const {
    m_xor_blocks(block, m_key_schedule[0]);

    for (std::size_t i = 1; i < m_rounds; ++i) {
        m_sub_bytes(block);
        m_shift_rows(block);
        m_mix_columns(block);
        m_xor_blocks(block, m_key_schedule[i]);
    }

    m_sub_bytes(block);
    m_shift_rows(block);
    m_xor_blocks(block, m_key_schedule.back());
}

void cipher::aes128::m_decrypt_block(byte_block& block) const {
    m_xor_blocks(block, m_key_schedule.back());

    for (std::size_t i = m_rounds - 1; i > 0; --i) {
        m_inv_sub_bytes(block);
        m_inv_shift_rows(block);
        m_inv_mix_columns(block);
        m_xor_blocks(block, m_key_schedule[i]);
    }

    m_inv_sub_bytes(block);
    m_inv_shift_rows(block);
    m_xor_blocks(block, m_key_schedule[0]);
}

cipher::aes128::aes128(const std::string_view& key) {
    m_key_expansion(key);
}
