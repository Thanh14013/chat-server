#pragma once
#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>

namespace vcs::crypto{
    class CSPRNG{
        public:
            static CSPRNG& getInstance();

            CSPRNG(const CSPRNG&) = delete;
            CSPRNG& operator=(const CSPRNG&) = delete;

            void getBytes(uint8_t* buf, size_t n) const;

            std::vector<uint8_t> getBytes(size_t n) const;

            uint32_t getUInt32() const;

            std::array<uint8_t, 16> getNonce() const;
        
        private:
            CSPRNG() = default;
    };
}