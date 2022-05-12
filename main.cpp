#include <iostream>
#include "testing_scenarios.h"
#include "tests.h"

void run_tests_for_testing_scenario(const std::function<std::string ()>& testing_scenario) {
    std::string seq = testing_scenario();
    std::cout << "Monobit test: " << monobit_test(seq) << std::endl;
    std::cout << "Runs test: " << runs_test(seq) << std::endl;
    std::cout << "Random excursion variant test: " << random_excursions_variant_test(seq) << std::endl;
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cout << std::boolalpha;

    return 0;
}
