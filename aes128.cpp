#include "aes128.h"
#include <execution>

void cipher::aes128::m_sub_word(std::array<uint8_t, 4>& word) {
	std::ranges::transform(word, word.begin(), [](uint8_t byte) {return aes::sbox[byte]; });
}

void cipher::aes128::m_rot_word(std::array<uint8_t, 4>& word, std::ptrdiff_t offset) {
	auto mid_iterator = (offset >= 0) ? word.begin() : word.end();
	std::ranges::rotate(word, mid_iterator + offset);
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
    for (uint8_t i = 0; i < 8; i++) {
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
	for (auto& word : state) {
		std::ranges::transform(word, word.begin(), [](uint8_t byte) {return aes::inv_sbox[byte]; });
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

cipher::aes128::byte_block cipher::aes128::generate_initialization_vector()
{
	byte_block initialization_vector;
	std::mt19937 generator(std::random_device{}());
	std::uniform_int_distribution<int> random_symbol(0, 255);

	for (auto& line : initialization_vector) {
		std::ranges::generate(line.begin(), line.end(), [&random_symbol, &generator]() -> uint8_t {return random_symbol(generator); });
	}

	return initialization_vector;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::get_blocks_array(const std::string_view& text, bool complete_last_block) {
	const int lines_num = 4;
	const int columns_num = 4;
	const int block_size = lines_num * columns_num;
	int blocks_num = text.length() / block_size;
	std::vector<byte_block> blocks_array(blocks_num);

	std::string line;
	for (int i = 0; i < blocks_num; i++) {
		for (int j = 0; j < lines_num; j++) {
			line = text.substr(i * block_size + j * columns_num, columns_num);
			std::ranges::transform(line, blocks_array[i][j].begin(), [](char chr) {return (uint8_t)(chr); });
		}
	}

	if (complete_last_block) {
		int num_of_added_elems = 0;
		byte_block block;
		if (text.length() % block_size != 0) {
			line = text.substr(text.length() / block_size * block_size);
			line.resize(block_size);

			std::string block_line;
			for (int i = 0; i < lines_num; i++) {
				block_line = line.substr(i * columns_num, columns_num);
				std::ranges::transform(block_line, block[i].begin(), [](char chr) {return (uint8_t)chr; });
			}
			blocks_array.push_back(block);
		}

		for (auto& block_line : block) {
			std::ranges::fill(block_line, num_of_added_elems);
		}
		blocks_array.push_back(block);
	}

	return blocks_array;
}

std::string cipher::aes128::get_string(std::vector<byte_block>& byte_blocks_array, bool delete_last_block) {
	std::string text;
	text.reserve(byte_blocks_array.size() * 16);

	const int lines_num = byte_blocks_array[0].size();
	std::string line(lines_num, ' ');

	int blocks_num = delete_last_block ? byte_blocks_array.size() - 1 : byte_blocks_array.size();

	for (int i = 0; i < blocks_num; i++) {
		for (int j = 0; j < byte_blocks_array[i].size(); j++) {
			std::ranges::transform(byte_blocks_array[i][j], line.begin(), [](uint8_t byte) {return (char)(byte); });
			text += line;
		}
	}

	if (!delete_last_block) {
		return text;
	}

	byte_block size_block = byte_blocks_array.back();
	int num_of_added_elems = size_block[0][0];

	text.erase(text.length() - num_of_added_elems);
	return text;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::encrypt_ecb(std::vector<byte_block>& plain_text_blocks) const {
	std::vector<cipher::aes128::byte_block> cipher_text_bocks = plain_text_blocks;
	std::for_each(std::execution::par, cipher_text_bocks.begin(), cipher_text_bocks.end(), [this](byte_block& block) {this->m_encrypt_block(block); });
	return cipher_text_bocks;
}
std::vector<cipher::aes128::byte_block> cipher::aes128::decrypt_ecb(std::vector<byte_block>& cipher_text_blocks)const {
	std::vector<cipher::aes128::byte_block> plain_text_blocks = cipher_text_blocks;
	std::for_each(std::execution::par, plain_text_blocks.begin(), plain_text_blocks.end(), [this](byte_block& block) {this->m_decrypt_block(block); });
	return plain_text_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::encrypt_cbc(std::vector<byte_block>& blocks_array) const
{
	std::vector<byte_block> encrypted_blocks_array(blocks_array.size() + 1);

	byte_block previous_block = generate_initialization_vector();
	encrypted_blocks_array[0] = previous_block;

	for (int i = 0; i < blocks_array.size(); i++)
	{
		cipher::aes128::m_xor_blocks(previous_block, blocks_array[i]);
		cipher::aes128::m_encrypt_block(previous_block);
		encrypted_blocks_array[i + 1] = previous_block;
	}

	return encrypted_blocks_array;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::decrypt_cbc(std::vector<byte_block>& blocks_array) const
{
	std::vector<byte_block> decrypted_blocks_array(blocks_array.size() - 1);

	for (int i = 1; i < blocks_array.size(); i++)
	{
		byte_block current_block = blocks_array[i];
		cipher::aes128::m_decrypt_block(current_block);
		cipher::aes128::m_xor_blocks(current_block, blocks_array[i - 1]);
		decrypted_blocks_array[i - 1] = current_block;
	}

	return decrypted_blocks_array;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::encrypt_cfb(std::vector<cipher::aes128::byte_block>& plain_text_blocks) const {
	std::vector<byte_block> cipher_text_blocks(plain_text_blocks.size() + 1);
	cipher_text_blocks[0] = generate_initialization_vector();
	byte_block block;
	for (int i = 1; i <= plain_text_blocks.size(); i++) {
		cipher_text_blocks[i] = cipher_text_blocks[i - 1];
		m_encrypt_block(cipher_text_blocks[i]);
		m_xor_blocks(cipher_text_blocks[i], plain_text_blocks[i - 1]);
		cipher_text_blocks[i];
	}

	return cipher_text_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::decrypt_cfb(std::vector<cipher::aes128::byte_block>& cipher_text_blocks) const {
	std::vector<byte_block> plain_text_blocks(cipher_text_blocks.size() - 1);
	byte_block block;
	for (int i = cipher_text_blocks.size() - 1; i >= 1; i--) {
		plain_text_blocks[i - 1] = cipher_text_blocks[i - 1];
		m_encrypt_block(plain_text_blocks[i - 1]);
		m_xor_blocks(plain_text_blocks[i - 1], cipher_text_blocks[i]);
	}
	return plain_text_blocks;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::encrypt_ofb(std::vector<byte_block>& blocks_array) const
{
	std::vector<byte_block> encrypted_blocks_array(blocks_array.size() + 1);

	byte_block previous_gamma = generate_initialization_vector();
	encrypted_blocks_array[0] = previous_gamma;

	for (int i = 0; i < blocks_array.size(); i++)
	{
		cipher::aes128::m_encrypt_block(previous_gamma);
		byte_block current_gamma = previous_gamma;
		cipher::aes128::m_xor_blocks(current_gamma, blocks_array[i]);
		encrypted_blocks_array[i + 1] = current_gamma;
	}

	return encrypted_blocks_array;
}

std::vector<cipher::aes128::byte_block> cipher::aes128::decrypt_ofb(std::vector<byte_block>& blocks_array) const
{
	std::vector<byte_block> decrypted_blocks_array(blocks_array.size() - 1);
	byte_block previous_gamma = blocks_array[0];

	for (int i = 1; i < blocks_array.size(); i++)
	{
		cipher::aes128::m_encrypt_block(previous_gamma);
		byte_block current_gamma = previous_gamma;
		cipher::aes128::m_xor_blocks(current_gamma, blocks_array[i]);
		decrypted_blocks_array[i - 1] = current_gamma;
	}

	return decrypted_blocks_array;
}

cipher::aes128::aes128(const std::string_view& key) {
	m_key_expansion(MD5(key).decimal_digest());
}

std::string cipher::aes128::encrypt(const std::string_view& plain_text, cipher::mode cipher_mode) const {
	std::vector<byte_block> plain_text_blocks_array = get_blocks_array(plain_text, true);
	std::vector<byte_block> cipher_text_blocks_array;

	switch (cipher_mode) {
	case cipher::mode::ecb:
		cipher_text_blocks_array = encrypt_ecb(plain_text_blocks_array);
		break;
	case cipher::mode::cbc:
		cipher_text_blocks_array = encrypt_cbc(plain_text_blocks_array);
		break;
	case cipher::mode::cfb:
		cipher_text_blocks_array = encrypt_cfb(plain_text_blocks_array);
		break;
	case cipher::mode::ofb:
		cipher_text_blocks_array = encrypt_ofb(plain_text_blocks_array);
		break;
	}

	return get_string(cipher_text_blocks_array, false);
}

std::string cipher::aes128::decrypt(const std::string_view& cipher_text, cipher::mode cipher_mode) const {
	std::vector<byte_block> cipher_text_blocks_array = get_blocks_array(cipher_text, false);
	std::vector<byte_block> plain_text_blocks_array;

	switch (cipher_mode) {
	case cipher::mode::ecb:
		plain_text_blocks_array = decrypt_ecb(cipher_text_blocks_array);
		break;
	case cipher::mode::cbc:
		plain_text_blocks_array = decrypt_cbc(cipher_text_blocks_array);
		break;
	case cipher::mode::cfb:
		plain_text_blocks_array = decrypt_cfb(cipher_text_blocks_array);
		break;
	case cipher::mode::ofb:
		plain_text_blocks_array = decrypt_ofb(cipher_text_blocks_array);
		break;
	}

	return get_string(plain_text_blocks_array, true);
}