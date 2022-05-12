#include <iostream>
#include "testing_scenarios.h"
#include "tests.h"

void run_tests_for_sequence(const std::string& seq) {
    std::cout << "Monobit test: " << monobit_test(seq) << std::endl;
    std::cout << "Runs test: " << runs_test(seq) << std::endl;
    std::cout << "Random excursion variant test: " << random_excursions_variant_test(seq) << std::endl;
}

void run_tests_for_cipher_modes() {
    cipher::aes128 aes("coolkey");
    std::string plain_text = "Cryptographic methods";

    std::string encryption_ecb = aes.encrypt(plain_text);
    std::string encryption_cbc = aes.encrypt(plain_text, cipher::mode::cbc);
    std::string encryption_ofb = aes.encrypt(plain_text, cipher::mode::ofb);
    std::string encryption_cfb = aes.encrypt(plain_text, cipher::mode::cfb);

    std::cout << "Encrypt ECB: " << encryption_ecb << std::endl;
    std::cout << "Encrypt CBC: " << encryption_cbc << std::endl;
    std::cout << "Encrypt OFB: " << encryption_ofb << std::endl;
    std::cout << "Encrypt CFB: " << encryption_cfb << std::endl;

    std::cout << "\nDecrypt ECB: " << aes.decrypt(encryption_ecb) << std::endl;
    std::cout << "Decrypt CBC: " << aes.decrypt(encryption_cbc, cipher::mode::cbc) << std::endl;
    std::cout << "Decrypt OFB: " << aes.decrypt(encryption_ofb, cipher::mode::ofb) << std::endl;
    std::cout << "Decrypt CFB: " << aes.decrypt(encryption_cfb, cipher::mode::cfb) << std::endl;
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cout << std::boolalpha;

    std::cout << "Random plain text and key\n";
    run_tests_for_sequence(random_plain_text_and_key());

    std::cout << "\nLow weight plaintext random key\n";
    run_tests_for_sequence(low_weight_plaintext_random_key());

    std::cout << "\nHeavy weight plaintext random key\n";
    run_tests_for_sequence(heavy_weight_plaintext_random_key());

    std::cout << "\nRandom plain text low weight key\n";
    run_tests_for_sequence(random_plaintext_low_weight_key());

    std::cout << "\nRandom plain text heavy weight key\n";
    run_tests_for_sequence(random_plaintext_heavy_weight_key());

    std::cout << "\nRandom plain text, key with errors\n";
    run_tests_for_sequence(random_plain_text_key_errors());

    std::cout << "\nPlain text with errors, random key\n";
    run_tests_for_sequence(plain_text_errors_random_key());

    std::cout << "\nPlain text and ciphertext correlation\n";
    run_tests_for_sequence(plain_text_and_chipertext_correlation());

    std::cout << "\nBlock chain processing\n";
    run_tests_for_sequence(block_chain_processing());
    std::cout << std::endl;

    run_tests_for_cipher_modes();

    return 0;
}
