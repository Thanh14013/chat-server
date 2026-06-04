#include "random.h"

#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

namespace vcs::crypto {

CSPRNG& CSPRNG::getInstance() {
    static CSPRNG instance;
    return instance;
}

void CSPRNG::getBytes(uint8_t* buf, size_t n) const {
    if (n == 0) return;
    if (RAND_bytes(buf, static_cast<int>(n)) != 1) {
        throw std::runtime_error("CSPRNG: RAND_bytes failed — insufficient entropy");
    }
}

std::vector<uint8_t> CSPRNG::getBytes(size_t n) const {
    std::vector<uint8_t> buf(n);
    getBytes(buf.data(), n);
    return buf;
}

uint32_t CSPRNG::getUInt32() const {
    uint32_t val = 0;
    getBytes(reinterpret_cast<uint8_t*>(&val), sizeof(val));
    return val;
}

std::array<uint8_t, 16> CSPRNG::getNonce() const {
    std::array<uint8_t, 16> nonce{};
    getBytes(nonce.data(), 16);
    return nonce;
}

} // namespace vcs::crypto
