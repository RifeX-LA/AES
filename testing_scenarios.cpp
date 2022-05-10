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
