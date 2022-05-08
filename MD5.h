#ifndef BZF_MD5_H
#define BZF_MD5_H

#include <cstring>
#include <string_view>

class MD5 {
public:
    typedef unsigned int size_type;

    MD5();
    MD5(const std::string_view &text);

    void update(const unsigned char *buf, size_type length);
    void update(const char *buf, size_type length);
    MD5 &finalize();

    const uint8_t* decimal_digest() const;

private:
    void init();

    enum {
        blocksize = 64
    };

    bool finalized;
    uint8_t buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk
    uint32_t count[2];   // 64bit counter for number of bits (lo, hi)
    uint32_t state[4];   // digest so far
    uint8_t digest[16]; // the result

    void transform(const uint8_t block[blocksize]);
    static void decode(uint32_t output[], const uint8_t input[], size_type len);
    static void encode(uint8_t output[], const uint32_t input[], size_type len);

    // low level logic operations
    static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z);
    static inline uint32_t rotate_left(uint32_t x, int n);
    static inline void FF(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
    static inline void GG(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
    static inline void HH(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
    static inline void II(uint32_t &a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac);
};

#endif