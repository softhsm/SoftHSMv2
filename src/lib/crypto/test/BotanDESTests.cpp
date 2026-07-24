// Unit tests for BotanDES
// Framework: GoogleTest (preferred if available). If your project uses a different framework,
// adapt the includes and assertions to match existing conventions.
#include "BotanDES.h"
#include "SymmetricKey.h"
#include "ByteString.h"
#include "RNG.h"
#include "config.h"

#ifdef HAVE_GTEST
#include <gtest/gtest.h>
#define TEST_SUITE(TESTNAME) TEST(TESTNAME, Run)
#define TEST_CASE(TESTNAME, CASENAME) TEST(TESTNAME, CASENAME)
#define EXPECT_STR_EQ EXPECT_STREQ
#else
// Fallback minimal assertions if gtest is not available; adapt as needed.
#include <cassert>
#include <iostream>
#define TEST_CASE(TESTNAME, CASENAME) static void TESTNAME##_##CASENAME(); \
  struct TESTNAME##_##CASENAME##_Runner { TESTNAME##_##CASENAME##_Runner(){ TESTNAME##_##CASENAME(); }} TESTNAME##_##CASENAME##_runner; \
  static void TESTNAME##_##CASENAME()
#define EXPECT_EQ(a,b) assert((a)==(b))
#define EXPECT_TRUE(a) assert((a))
#define EXPECT_FALSE(a) assert(!(a))
#define EXPECT_STR_EQ(a,b) assert(std::string(a)==std::string(b))
#endif

// Minimal Test RNG to control random output deterministically
class TestRNG : public RNG {
public:
    explicit TestRNG(const ByteString& seq) : seq_(seq), off_(0) {}
    bool generateRandom(ByteString& out, size_t bytes) override {
        out.resize(bytes);
        for (size_t i=0;i<bytes;i++) {
            out[i] = seq_[ (off_++) % seq_.size() ];
        }
        return true;
    }
private:
    ByteString seq_;
    size_t off_;
};

static ByteString mkBytes(std::initializer_list<unsigned char> v) {
    ByteString b;
    b.resize(v.size());
    size_t i=0;
    for (auto c: v) b[i++] = c;
    return b;
}

TEST_CASE(BotanDES_GetCipher, ReturnsEmptyWhenNoKey) {
    BotanDES des;
    // Ensure default state has no key set
    std::string out = des.getCipher();
    EXPECT_TRUE(out.empty());
}

TEST_CASE(BotanDES_GetCipher, DESKeySizesReturnDESAlgo) {
    BotanDES des;

    // Prepare a 56-bit key (8 bytes with parity later); set directly
    SymmetricKey key56;
    key56.setBitLen(56);
    key56.setKeyBits(mkBytes({0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF}));
    EXPECT_TRUE(des.setKey(&key56));

    des.setCipherMode(SymMode::CBC);
    des.setPaddingMode(true);
    EXPECT_EQ(std::string("DES/CBC/PKCS7"), des.getCipher());

    // 64 bits should still map to DES
    SymmetricKey key64;
    key64.setBitLen(64);
    key64.setKeyBits(mkBytes({0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10}));
    EXPECT_TRUE(des.setKey(&key64));

    des.setCipherMode(SymMode::ECB);
    des.setPaddingMode(false);
    EXPECT_EQ(std::string("DES/ECB/NoPadding"), des.getCipher());
}

TEST_CASE(BotanDES_GetCipher, TripleDESKeySizesReturnTripleDESAlgo) {
    BotanDES des;

    // 112-bit (16 bytes pre-parity) and 128-bit representations should both be TripleDES
    SymmetricKey key112;
    key112.setBitLen(112);
    key112.setKeyBits(ByteString(16, 0x11));
    EXPECT_TRUE(des.setKey(&key112));
    des.setCipherMode(SymMode::CFB);
    // CFB has no padding suffix
    des.setPaddingMode(true); // shouldn't matter for CFB
    EXPECT_EQ(std::string("TripleDES/CFB"), des.getCipher());

    SymmetricKey key168;
    key168.setBitLen(168);
    key168.setKeyBits(ByteString(24, 0x22));
    EXPECT_TRUE(des.setKey(&key168));
    des.setCipherMode(SymMode::OFB);
    // OFB has no padding suffix
    des.setPaddingMode(false);
    EXPECT_EQ(std::string("TripleDES/OFB"), des.getCipher());
}

TEST_CASE(BotanDES_GetCipher, InvalidModeOrKeyLenYieldEmpty) {
    BotanDES des;

    SymmetricKey badKey;
    badKey.setBitLen(40); // invalid
    badKey.setKeyBits(ByteString(5, 0xAA));
    EXPECT_TRUE(des.setKey(&badKey));

    // Invalid key length should yield empty string
    EXPECT_TRUE(des.getCipher().empty());

    // Valid key, but invalid mode id
    SymmetricKey key56;
    key56.setBitLen(56);
    key56.setKeyBits(ByteString(8, 0x55));
    EXPECT_TRUE(des.setKey(&key56));

    des.setCipherMode(static_cast<SymMode>(-1)); // invalid
    EXPECT_TRUE(des.getCipher().empty());
}

TEST_CASE(BotanDES_PaddingBehavior, PaddingSuffixRules) {
    BotanDES des;
    SymmetricKey key;
    key.setBitLen(56);
    key.setKeyBits(ByteString(8, 0x01));
    EXPECT_TRUE(des.setKey(&key));

    des.setCipherMode(SymMode::CBC);
    des.setPaddingMode(true);
    EXPECT_EQ(std::string("DES/CBC/PKCS7"), des.getCipher());

    des.setPaddingMode(false);
    EXPECT_EQ(std::string("DES/CBC/NoPadding"), des.getCipher());

    des.setCipherMode(SymMode::CFB);
    des.setPaddingMode(true);
    EXPECT_EQ(std::string("DES/CFB"), des.getCipher());

    des.setCipherMode(SymMode::OFB);
    des.setPaddingMode(false);
    EXPECT_EQ(std::string("DES/OFB"), des.getCipher());
}

TEST_CASE(BotanDES_GenerateKey, RequiresRngAndBitLen) {
    BotanDES des;
    SymmetricKey keyNoLen;
    TestRNG rng(ByteString(1, 0x00));

    // No bit length set -> fail
    EXPECT_FALSE(des.generateKey(keyNoLen, &rng));

    // RNG null -> fail
    SymmetricKey key56;
    key56.setBitLen(56);
    EXPECT_FALSE(des.generateKey(key56, nullptr));
}

TEST_CASE(BotanDES_GenerateKey, GeneratesWithOddParityAndCorrectLength) {
    BotanDES des;

    // Use a deterministic RNG that cycles through 0x00..0xFF sequence
    ByteString seq(256);
    for (size_t i=0;i<256;i++) seq[i] = static_cast<unsigned char>(i);
    TestRNG rng(seq);

    // 56-bit (8 bytes after parity)
    SymmetricKey key56;
    key56.setBitLen(56);
    EXPECT_TRUE(des.generateKey(key56, &rng));
    ByteString kb56 = key56.getKeyBits();
    EXPECT_EQ(static_cast<size_t>(8), kb56.size());
    // Each byte should have odd parity bit applied (we spot-check a few)
    // Count bits helper
    auto popcnt = [](unsigned char x){ int c=0; for(int i=0;i<8;i++) c += (x>>i)&1; return c; };
    EXPECT_TRUE((popcnt(kb56[0]) % 2) == 1);
    EXPECT_TRUE((popcnt(kb56[1]) % 2) == 1);

    // 168-bit (24 bytes after parity)
    SymmetricKey key168;
    key168.setBitLen(168);
    EXPECT_TRUE(des.generateKey(key168, &rng));
    ByteString kb168 = key168.getKeyBits();
    EXPECT_EQ(static_cast<size_t>(24), kb168.size());
    EXPECT_TRUE((popcnt(kb168[0]) % 2) == 1);
    EXPECT_TRUE((popcnt(kb168[23]) % 2) == 1);
}

TEST_CASE(BotanDES_BlockSize, ReturnsEightBytes) {
    BotanDES des;
    EXPECT_EQ(static_cast<size_t>(8), des.getBlockSize());
}

TEST_CASE(BotanDES_WrapUnwrapKey, NotSupported) {
    BotanDES des;
    ByteString in(8, 0x00), out;
    SymmetricKey anyKey; anyKey.setBitLen(56); anyKey.setKeyBits(ByteString(8, 0x00));
    EXPECT_FALSE(des.wrapKey(&anyKey, SymWrap::Type::Unknown, in, out));
    EXPECT_FALSE(des.unwrapKey(&anyKey, SymWrap::Type::Unknown, in, out));
}