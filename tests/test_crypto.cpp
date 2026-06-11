#include "TestMacro.h"
#include "../crypto/aes.h"
#include "../crypto/rsa.h"
#include "../crypto/hmac.h"
#include "../crypto/sha256.h"
#include "../crypto/random.h"
#include <vector>
#include <string>

using namespace vcs::crypto;

void test_aes() {
    auto key = CSPRNG::getInstance().getBytes(32);
    AES256GCM aes(key);

    std::vector<uint8_t> pt = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> aad = {'h', 'e', 'a', 'd', 'e', 'r'};

    auto ct = aes.encrypt(pt, aad);
    auto dec = aes.decrypt(ct, aad);
    ASSERT_TRUE(pt == dec);

    std::vector<uint8_t> bad_aad = {'b', 'a', 'd'};
    ASSERT_THROWS(aes.decrypt(ct, bad_aad), std::runtime_error);

    auto bad_ct = ct;
    bad_ct[0] ^= 1;
    ASSERT_THROWS(aes.decrypt(bad_ct, aad), std::runtime_error);

    auto ct_empty = aes.encrypt({}, aad);
    auto dec_empty = aes.decrypt(ct_empty, aad);
    ASSERT_EQ(0, dec_empty.size());

    // Edge case: bad key size
    std::vector<uint8_t> bad_key = {'1', '2', '3'};
    ASSERT_THROWS(AES256GCM(bad_key), std::runtime_error);

    // Edge case: too short ciphertext
    std::vector<uint8_t> short_ct = {'1', '2', '3'};
    ASSERT_THROWS(aes.decrypt(short_ct, aad), std::runtime_error);

    // Edge case: tampered tag (last 16 bytes)
    auto tampered_tag_ct = ct;
    tampered_tag_ct[tampered_tag_ct.size() - 1] ^= 1;
    ASSERT_THROWS(aes.decrypt(tampered_tag_ct, aad), std::runtime_error);
}

void test_rsa() {
    RSA2048 rsa1;
    rsa1.generateKeyPair();
    
    std::vector<uint8_t> data = {'d', 'a', 't', 'a'};

    auto pem = rsa1.getPublicKeyPEM();
    
    RSA2048 verifier;
    verifier.loadPublicKeyPEM(pem);

    auto enc = verifier.encrypt(data);
    auto dec = rsa1.decrypt(enc);
    ASSERT_TRUE(data == dec);

    auto bad_enc = enc;
    bad_enc[0] ^= 1;
    ASSERT_THROWS(rsa1.decrypt(bad_enc), std::runtime_error);

    // Edge case: invalid PEM load
    ASSERT_THROWS(verifier.loadPublicKeyPEM("INVALID PEM STRING"), std::runtime_error);

    // Edge case: oversized data encryption (RSA 2048 with OAEP/PKCS1 limits to ~245 bytes)
    std::vector<uint8_t> oversized(300, 'A');
    ASSERT_THROWS(verifier.encrypt(oversized), std::runtime_error);
}

void test_hmac() {
    std::string data = "message";
    std::vector<uint8_t> key = {'s', 'e', 'c', 'r', 'e', 't'};
    
    auto sig1 = HMACSHA256::compute(data, key);
    auto sig2 = HMACSHA256::compute(data, key);
    ASSERT_TRUE(sig1 == sig2);
    ASSERT_TRUE(HMACSHA256::verify(data, key, sig1));

    std::vector<uint8_t> bad_key = {'w', 'r', 'o', 'n', 'g'};
    ASSERT_FALSE(HMACSHA256::verify(data, bad_key, sig1));

    auto bad_sig = sig1;
    bad_sig[0] ^= 1;
    ASSERT_FALSE(HMACSHA256::verify(data, key, bad_sig));

    // Edge case: empty data
    auto sig_empty = HMACSHA256::compute("", key);
    ASSERT_TRUE(HMACSHA256::verify("", key, sig_empty));

    // Edge case: empty key (OpenSSL HMAC_Init_ex rejects this and throws)
    ASSERT_THROWS(HMACSHA256::compute(data, {}), std::runtime_error);
}

void test_sha256() {
    std::string data = "hello world";
    std::string hash1 = SHA256Hash::hash(data);
    std::string hash2 = SHA256Hash::hash(data);
    ASSERT_EQ(hash1, hash2);
    ASSERT_EQ(64, hash1.size()); // hex string

    // Edge case: empty string hash
    std::string empty_hash = SHA256Hash::hash("");
    // SHA256("") is e3b0c442...
    ASSERT_EQ(64, empty_hash.size());
}

void test_random() {
    auto b1 = CSPRNG::getInstance().getBytes(16);
    auto b2 = CSPRNG::getInstance().getBytes(16);
    ASSERT_EQ(16, b1.size());
    ASSERT_EQ(16, b2.size());
    ASSERT_TRUE(b1 != b2);

    // Edge case: request 0 bytes
    auto b0 = CSPRNG::getInstance().getBytes(0);
    ASSERT_EQ(0, b0.size());
}

int main() {
    RUN_TEST(test_aes);
    RUN_TEST(test_rsa);
    RUN_TEST(test_hmac);
    RUN_TEST(test_sha256);
    RUN_TEST(test_random);
    return test::PrintTestResults("Crypto Module");
}
