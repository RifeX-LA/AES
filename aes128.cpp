#include "aes128.h"

void cipher::aes128::m_sub_word(std::array<uint8_t, 4>& word) {
    std::ranges::transform(word, word.begin(), [](uint8_t byte) {return aes::sbox[byte];});
}

void cipher::aes128::m_rot_word(std::array<uint8_t, 4>& word, std::ptrdiff_t offset) {
    auto mid_iterator = (offset >= 0) ? word.begin() : word.end();
    std::ranges::rotate(word, mid_iterator + offset);
}

uint8_t cipher::aes128::m_gmul(uint8_t a, uint8_t b) {
    if (a < b) {
        uint8_t tmp = a;
        a = b;
        b = tmp;
    }

    switch (b) {
    case 1:
        return a;
    case 2:
        bool fl = a < 0x80;
        a <<= 1;
        return fl ? a : a ^ 0x1b;
    }

    uint8_t ans = 0, m = 2;
    if (b & 1) {
        ans ^= a;
    }
    for (std::size_t i = 1; i < 8; ++i, m <<= 1) {
        if (!(b & m)) {
            continue;
        }
        uint8_t c = a;
        for (std::size_t j = 0; j < i; ++j) {
            c = m_gmul(c, 2);
        }
        ans ^= c;
    }
    return ans;
}

void cipher::aes128::m_byte_block_transpose(byte_block& block) {
    auto temp = block;
    for (std::size_t i = 0; i < block.size(); ++i) {
        for (std::size_t j = 0; j < block[i].size(); ++j) {
            block[i][j] = temp[j][i];
        }
    }
}

void cipher::aes128::m_key_expansion(const uint8_t* key) {
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
    std::ranges::for_each(state, m_sub_word);
}

void cipher::aes128::m_shift_rows(byte_block& state) {
    for (std::ptrdiff_t i = 1; i < state.size(); ++i) {
        m_rot_word(state[i], i);
    }
}

void cipher::aes128::m_mix_columns(byte_block& state) {
    for (std::size_t i = 0; i < state.size(); ++i) {
        uint8_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        for (std::size_t j = 0; j < state.size(); ++j) {
            s0 ^= m_gmul(state[j][i], aes::mix_columns_op[0][j]);
            s1 ^= m_gmul(state[j][i], aes::mix_columns_op[1][j]);
            s2 ^= m_gmul(state[j][i], aes::mix_columns_op[2][j]);
            s3 ^= m_gmul(state[j][i], aes::mix_columns_op[3][j]);
        }
        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
}

void cipher::aes128::m_inv_sub_bytes(byte_block& state) {
    for (auto& word : state) {
        std::ranges::transform(word, word.begin(), [](uint8_t byte) {return aes::inv_sbox[byte];});
    }
}

void cipher::aes128::m_inv_shift_rows(byte_block& state) {
    for (std::ptrdiff_t i = 1; i < state.size(); ++i) {
        m_rot_word(state[i], -i);
    }
}

void cipher::aes128::m_inv_mix_columns(byte_block& state) {
    for (std::size_t i = 0; i < state.size(); ++i) {
        uint8_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        for (std::size_t j = 0; j < state.size(); ++j) {
            s0 ^= m_gmul(state[j][i], aes::inv_mix_columns_op[0][j]);
            s1 ^= m_gmul(state[j][i], aes::inv_mix_columns_op[1][j]);
            s2 ^= m_gmul(state[j][i], aes::inv_mix_columns_op[2][j]);
            s3 ^= m_gmul(state[j][i], aes::inv_mix_columns_op[3][j]);
        }
        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
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
        m_xor_blocks(block, m_key_schedule[i]);
        m_inv_mix_columns(block);
    }

    m_inv_sub_bytes(block);
    m_inv_shift_rows(block);
    m_xor_blocks(block, m_key_schedule[0]);
}

cipher::aes128::aes128(const std::string_view& key) {
    m_key_expansion(MD5(key).decimal_digest());
}
