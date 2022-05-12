#include "testing_scenarios.h"

std::string xor_strings(const std::string_view& lhs, const std::string_view& rhs) {
    std::string result_str(lhs.size(), 0);
    std::ranges::transform(lhs, rhs, result_str.begin(), std::bit_xor<>());

    return result_str;
}

std::string random_string(std::size_t size) {
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<int> random_symbol(0, 127);

    std::string str(size, 0);
    std::ranges::generate(str, [&gen, &random_symbol]() -> char { return random_symbol(gen); });

    return str;
}

std::string generate_heavy_or_little_weight_string_block(int start_elem) {
    std::mt19937 gen(std::random_device{}());

    std::string string_block(16, (256 - start_elem) % 256);

    std::uniform_int_distribution<int> random_symbol_from_0_to_2(0, 2);
    int weight = random_symbol_from_0_to_2(gen);

    std::uniform_int_distribution<int> random_symbol_from_0_to_3(0, 3);
    std::uniform_int_distribution<int> random_bit_from_0_to_7(0, 7);

    for (int k = 0; k < weight; k++) {
        int i = random_symbol_from_0_to_3(gen);
        int j = random_symbol_from_0_to_3(gen);
        int position_of_bit_to_change = random_bit_from_0_to_7(gen);
        char pow_of_two = pow(2, position_of_bit_to_change);
        string_block[i * 4 + j] ^= pow_of_two;
    }

    return string_block;
}

std::string low_or_heavy_weight_plaintext_random_key(int start_elem) {
    constexpr std::size_t blocks_of_plain_text_num = 65'536;

    cipher::aes128 aes(random_string(16));
    std::string ciphertext;
    ciphertext.reserve(bytes_in_megabyte);

    for (std::size_t i = 0; i < blocks_of_plain_text_num; ++i) {
        std::string string_block = generate_heavy_or_little_weight_string_block(start_elem);
        ciphertext += aes.encrypt(string_block, cipher::mode::ecb, false);
    }

    return ciphertext;
}

std::string random_plaintext_low_or_heavy_weight_key(int start_elem) {
    constexpr std::size_t blocks_of_plain_text_num = 65'536;

    cipher::aes128 aes(generate_heavy_or_little_weight_string_block(start_elem));
    std::string ciphertext;
    ciphertext.reserve(bytes_in_megabyte);

    for (std::size_t i = 0; i < blocks_of_plain_text_num; ++i) {
        std::string string_block = random_string(16);
        ciphertext += aes.encrypt(string_block, cipher::mode::ecb, false);
    }

    return ciphertext;
}

std::string low_weight_plaintext_random_key() {
    return low_or_heavy_weight_plaintext_random_key(0);
}

std::string heavy_weight_plaintext_random_key() {
    return low_or_heavy_weight_plaintext_random_key(1);
}

std::string random_plaintext_low_weight_key() {
    return random_plaintext_low_or_heavy_weight_key(0);
}

std::string random_plaintext_heavy_weight_key() {
    return random_plaintext_low_or_heavy_weight_key(1);
}

std::string random_plain_text_and_key() {
    cipher::aes128 aes(random_string(16));
    return aes.encrypt(random_string(bytes_in_megabyte), cipher::mode::ecb, false);
}

std::string random_plain_text_key_errors() {
    constexpr std::size_t key_len = 16;
    constexpr std::size_t plain_text_size = bytes_in_megabyte / key_len;

    std::string text(plain_text_size, 0);
    std::string result_str;
    result_str.reserve(bytes_in_megabyte);

    for (std::size_t i = 0; i < key_len; ++i) {
        std::string key = random_string(key_len);
        std::string encrypted = cipher::aes128(key).encrypt(text, cipher::mode::ecb, false);
        key[i] ^= 1;
        std::string encrypted_error_key = cipher::aes128(key).encrypt(text, cipher::mode::ecb, false);

        result_str += xor_strings(encrypted, encrypted_error_key);
    }

    return result_str;
}

std::string plain_text_errors_random_key() {
    const std::size_t plain_text_size = std::sqrt(bytes_in_megabyte);

    cipher::aes128 aes(std::string(16, 0));
    std::string result_str;
    result_str.reserve(bytes_in_megabyte);

    for (std::size_t i = 0; i < plain_text_size; ++i) {
        std::string plain_text = random_string(plain_text_size);
        std::string encrypted = aes.encrypt(plain_text, cipher::mode::ecb, false);
        plain_text[i] ^= 1;
        std::string encrypted_error_plain_text = aes.encrypt(plain_text, cipher::mode::ecb, false);

        result_str += xor_strings(encrypted, encrypted_error_plain_text);
    }

    return result_str;
}

std::string plain_text_and_chipertext_correlation() {
    std::string plain_text = random_string(bytes_in_megabyte);
    std::string ciphertext = cipher::aes128(random_string(16)).encrypt(plain_text, cipher::mode::ecb, false);

    return xor_strings(plain_text, ciphertext);
}

std::string block_chain_processing() {
    cipher::aes128 aes(random_string(16));
    std::string ciphertext(16, 0);
    std::string result_str;
    result_str.reserve(bytes_in_megabyte);

    for (std::size_t i = 0; i < bytes_in_megabyte / 16; ++i) {
        ciphertext = aes.encrypt(ciphertext, cipher::mode::ecb, false);
        result_str += ciphertext;
    }

    return result_str;
}
