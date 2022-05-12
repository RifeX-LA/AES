#include <cmath>
#include <bitset>
#include <iostream>
#include <algorithm>
#include "tests.h"

std::vector<bool> to_bit_vector(const std::string &sequence) {
	std::vector<bool> v;
	v.reserve(sequence.size() * 8);
	for (uint8_t a : sequence) {
		std::bitset<8> bs(a);
		for(int i = 7; i >= 0; --i) {
			v.push_back(bs[i]);
		}
	}
	return v;
}

bool monobit_test(const std::string &sequence) {
	auto seq = to_bit_vector(sequence);
	double sum = 0;
	for (bool bit : seq) {
		sum += bit ? 1 : -1;
	}
	return erfc(std::abs(sum) / (sqrt(2 * seq.size()))) >= 0.01;
}

bool runs_test(const std::string &sequence) {
	auto seq = to_bit_vector(sequence);
	int n = seq.size();
	double tau = 2 / sqrt(n);
	double pi = static_cast<double>(std::ranges::count(seq, 1)) / n;
	if (std::abs(pi - 0.5) >= tau) {
		return false;
	}
	int V = 1;
	for (std::size_t i = 0; i < n - 1; ++i) {
		V += seq[i] != seq[i + 1];
	}
	return erfc(std::abs(V - 2 * pi * n * (1 - pi)) / (2 * sqrt(2 * n) * pi * (1 - pi))) >= 0.01;
}

bool random_excursions_variant_test(const std::string& sequence) {
	auto seq = to_bit_vector(sequence);
	int n = sequence.size();
	long long j = 1;
	std::vector<int> s(n + 2, 0);
	std::vector<int> xi(2 * (n - 1), 0);
	s[1] = seq[0] ? 1 : -1;
	++xi[s[1] + (n - 1)];
	for (int i = 1; i < n + 1; ++i) {
		s[i] = s[i - 1] + (seq[i - 1] ? 1 : -1);
		j += s[i] == 0 ? 1 : 0;
		++xi[s[i] + (n - 1)];
	}
	for (int i = 0; i < xi.size(); ++i) {
		long long x = i < n - 1 ? i - n + 1 : i - n + 2;
		double P = erfc(std::abs(xi[i] - j) / sqrt(2 * j * (4 * std::abs(x) - 2)));
		if (P < 0.01) {
			return false;
		}
	}
	return true;
}
