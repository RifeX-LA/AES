#include "aes128.h"

void cipher::aes128::m_sub_word(std::array<uint8_t, 4>& word) {
    std::ranges::transform(word, word.begin(), [](uint8_t byte) { return aes::sbox[byte]; });
}

void cipher::aes128::m_rot_word(std::array<uint8_t, 4>& word, std::ptrdiff_t offset) {
    auto mid_iterator = (offset >= 0) ? word.begin() : word.end();
    std::rotate(word.begin(), mid_iterator + offset, word.end());
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

uint8_t cipher::aes128::m_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (std::size_t i = 0; i < 8; ++i) {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void cipher::aes128::m_multiply_matrix_by_columns(byte_block& state, const byte_block& op_table) {
    for (std::size_t i = 0; i < state.size(); ++i) {
        uint8_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        for (std::size_t j = 0; j < state.size(); ++j) {
            s0 ^= m_gmul(state[j][i], op_table[0][j]);
            s1 ^= m_gmul(state[j][i], op_table[1][j]);
            s2 ^= m_gmul(state[j][i], op_table[2][j]);
            s3 ^= m_gmul(state[j][i], op_table[3][j]);
        }
        state[0][i] = s0;
        state[1][i] = s1;
        state[2][i] = s2;
        state[3][i] = s3;
    }
}

void cipher::aes128::m_mix_columns(byte_block& state) {
    m_multiply_matrix_by_columns(state, aes::mix_columns_op);
}

void cipher::aes128::m_inv_sub_bytes(byte_block& state) {
    for (auto& word: state) {
        std::ranges::transform(word, word.begin(), [](uint8_t byte) { return aes::inv_sbox[byte]; });
    }
}

void cipher::aes128::m_inv_shift_rows(byte_block& state) {
    for (std::ptrdiff_t i = 1; i < state.size(); ++i) {
        m_rot_word(state[i], -i);
    }
}

void cipher::aes128::m_inv_mix_columns(byte_block& state) {
    m_multiply_matrix_by_columns(state, aes::inv_mix_columns_op);
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

cipher::aes128::byte_block cipher::aes128::generate_initialization_vector() {
    byte_block initialization_vector;
    std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<int> random_symbol(0, 255);

    for (auto& row: initialization_vector) {
        std::ranges::generate(row, [&random_symbol, &generator]() -> uint8_t { return random_symbol(generator); });
    }

    return initialization_vector;
}

std::vector<cipher::aes128::byte_block>
cipher::aes128::m_to_byte_blocks(const std::string_view& text, bool complete_last_block) {
    constexpr std::size_t lines_num = 4;
    constexpr std::size_t columns_num = 4;
    constexpr std::size_t block_size = lines_num * columns_num;

    const std::size_t blocks_num = text.size() / block_size;
    std::vector<byte_block> blocks(blocks_num);

    for (std::size_t i = 0; i < blocks_num; ++i) {
        for (std::size_t j = 0; j < lines_num; ++j) {
            auto text_block_begin = text.begin() + (i * block_size + j * columns_num);
            std::copy(text_block_begin, text_block_begin + columns_num, blocks[i][j].begin());
        }
    }

    if (complete_last_block) {
        byte_block block;
        std::size_t num_of_added_elems = 0;

        if (text.size() % block_size != 0) {
            std::string line;
            line = text.substr(text.size() / block_size * block_size);
            num_of_added_elems = block_size - line.size();
            line.resize(block_size);

            for (std::size_t i = 0; i < lines_num; ++i) {
                auto text_block_begin = line.begin() + i * columns_num;
                std::copy(text_block_begin, text_block_begin + columns_num, block[i].begin());
            }
            blocks.push_back(block);
        }

        for (auto& block_line: block) {
            std::ranges::fill(block_line, num_of_added_elems);
        }
        blocks.push_back(block);
    }

    return blocks;
}

std::string cipher::aes128::m_to_text(const std::vector<byte_block>& byte_blocks, bool delete_last_block) {
    int blocks_num = delete_last_block ? byte_blocks.size() - 1 : byte_blocks.size();
    std::string text;
    text.reserve(blocks_num * 16);

    for (int i = 0; i < blocks_num; ++i) {
        for (const auto& word : byte_blocks[i]) {
            std::ranges::copy(word, std::back_inserter(text));
        }
    }

    if (delete_last_block) {
        byte_block size_block = byte_blocks.back();
        std::size_t added_elems_num = size_block[0][0];
        text.erase(text.size() - added_elems_num);
    }

    return text;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::m_encrypt_ecb(const std::vector<byte_block>& plain_byte_blocks) const {
    std::vector<byte_block> cipher_byte_blocks = plain_byte_blocks;
    std::for_each(std::execution::par, cipher_byte_blocks.begin(), cipher_byte_blocks.end(),
                  [this](byte_block& block) { this->m_encrypt_block(block); });
    return cipher_byte_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::m_decrypt_ecb(const std::vector<byte_block>& cipher_byte_blocks) const {
    std::vector<byte_block> plain_byte_blocks = cipher_byte_blocks;
    std::for_each(std::execution::par, plain_byte_blocks.begin(), plain_byte_blocks.end(),
                  [this](byte_block& block) { this->m_decrypt_block(block); });
    return plain_byte_blocks;
}

std::vector<cipher::aes128::byte_block>
cipher::aes128::m_encrypt_cbc(const std::vector<byte_block>& plain_byte_blocks) const {
    std::vector<byte_block> cipher_byte_blocks(plain_byte_blocks.size() + 1);

    byte_block previous_block = generate_initialization_vector();
    cipher_byte_blocks[0] = previous_block;

    for (int i = 0; i < plain_byte_blocks.size(); i++) {
        m_xor_blocks(previous_block, plain_byte_blocks[i]);
        m_encrypt_block(previous_block);
        cipher_byte_blocks[i + 1] = previous_block;
    }

    return cipher_byte_blocks;
}

std::vector<cipher::aes128::byte_block>
cipher::aes128::m_decrypt_cbc(const std::vector<byte_block>& cipher_byte_blocks) const {
    std::vector<byte_block> plain_byte_blocks(cipher_byte_blocks.size() - 1);

    for (int i = 1; i < cipher_byte_blocks.size(); i++) {
        byte_block current_block = cipher_byte_blocks[i];
        m_decrypt_block(current_block);
        m_xor_blocks(current_block, cipher_byte_blocks[i - 1]);
        plain_byte_blocks[i - 1] = current_block;
    }

    return plain_byte_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::m_encrypt_cfb(const std::vector<byte_block>& plain_byte_blocks) const {
    std::vector<byte_block> cipher_byte_blocks(plain_byte_blocks.size() + 1);
    cipher_byte_blocks[0] = generate_initialization_vector();
    for (std::size_t i = 1; i <= plain_byte_blocks.size(); ++i) {
        cipher_byte_blocks[i] = cipher_byte_blocks[i - 1];
        m_encrypt_block(cipher_byte_blocks[i]);
        m_xor_blocks(cipher_byte_blocks[i], plain_byte_blocks[i - 1]);
    }

    return cipher_byte_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::m_decrypt_cfb(const std::vector<byte_block>& cipher_byte_blocks) const {
    std::vector<byte_block> plain_byte_blocks(cipher_byte_blocks.size() - 1);
    for (int i = cipher_byte_blocks.size() - 1; i >= 1; --i) {
        plain_byte_blocks[i - 1] = cipher_byte_blocks[i - 1];
        m_encrypt_block(plain_byte_blocks[i - 1]);
        m_xor_blocks(plain_byte_blocks[i - 1], cipher_byte_blocks[i]);
    }

    return plain_byte_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::m_encrypt_ofb(const std::vector<byte_block>& plain_byte_blocks) const {
    std::vector<byte_block> cipher_byte_blocks(plain_byte_blocks.size() + 1);

    byte_block previous_gamma = generate_initialization_vector();
    cipher_byte_blocks[0] = previous_gamma;

    for (std::size_t i = 0; i < plain_byte_blocks.size(); ++i) {
        m_encrypt_block(previous_gamma);
        byte_block current_gamma = previous_gamma;
        m_xor_blocks(current_gamma, plain_byte_blocks[i]);
        cipher_byte_blocks[i + 1] = current_gamma;
    }

    return cipher_byte_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::m_decrypt_ofb(const std::vector<byte_block>& cipher_byte_blocks) const {
    std::vector<byte_block> plain_byte_blocks(cipher_byte_blocks.size() - 1);
    byte_block previous_gamma = cipher_byte_blocks[0];

    for (std::size_t i = 1; i < cipher_byte_blocks.size(); ++i) {
        m_encrypt_block(previous_gamma);
        byte_block current_gamma = previous_gamma;
        m_xor_blocks(current_gamma, cipher_byte_blocks[i]);
        plain_byte_blocks[i - 1] = current_gamma;
    }

    return plain_byte_blocks;
}

cipher::aes128::aes128(const std::string_view& key) {
    m_key_expansion(MD5(key).decimal_digest());
}

std::string cipher::aes128::encrypt(const std::string_view& plain_text, cipher::mode cipher_mode) const {
    std::vector<byte_block> plain_byte_blocks = m_to_byte_blocks(plain_text, true);
    std::vector<byte_block> cipher_byte_blocks;

    switch (cipher_mode) {
        case mode::ecb:
            cipher_byte_blocks = m_encrypt_ecb(plain_byte_blocks);
            break;
        case mode::cbc:
            cipher_byte_blocks = m_encrypt_cbc(plain_byte_blocks);
            break;
        case mode::cfb:
            cipher_byte_blocks = m_encrypt_cfb(plain_byte_blocks);
            break;
        case mode::ofb:
            cipher_byte_blocks = m_encrypt_ofb(plain_byte_blocks);
            break;
    }

    return m_to_text(cipher_byte_blocks, false);
}

std::string cipher::aes128::decrypt(const std::string_view& cipher_text, cipher::mode cipher_mode) const {
    std::vector<byte_block> cipher_byte_blocks = m_to_byte_blocks(cipher_text, false);
    std::vector<byte_block> plain_byte_blocks;

    switch (cipher_mode) {
        case mode::ecb:
            plain_byte_blocks = m_decrypt_ecb(cipher_byte_blocks);
            break;
        case mode::cbc:
            plain_byte_blocks = m_decrypt_cbc(cipher_byte_blocks);
            break;
        case mode::cfb:
            plain_byte_blocks = m_decrypt_cfb(cipher_byte_blocks);
            break;
        case mode::ofb:
            plain_byte_blocks = m_decrypt_ofb(cipher_byte_blocks);
            break;
    }

    return m_to_text(plain_byte_blocks, true);
}