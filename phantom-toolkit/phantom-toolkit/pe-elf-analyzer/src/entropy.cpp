// entropy.cpp
#include <cmath>
#include <cstdint>
#include <cstddef>
#include "../include/analyzer.h"

double shannon_entropy(const uint8_t *data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double h = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)len;
        h -= p * log2(p);
    }
    return h;
}
