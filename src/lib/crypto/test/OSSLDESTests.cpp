/*
 * OSSLDES unit tests
 *
 * Framework: GoogleTest (gtest)
 * If your project uses a different framework, you can map the ASSERT/EXPECT macros accordingly.
 */

#include <cstring>
#include <vector>
#include <algorithm>

#include "OSSLDES.h"
#include "ByteString.h"
#include "RNG.h"
#include "config.h"

#ifdef WITH_OPENSSL
// OpenSSL cipher includes are pulled via <openssl/evp.h> through OSSL headers
#include <openssl/evp.h>
#endif

// Prefer project-specific test header if it centralizes gtest
#ifdef HAS_GTEST
#include <gtest/gtest.h>
#else
#include <gtest/gtest.h>
#endif

// Minimal mock RNG to generate deterministic bytes and to validate generateRandom invocations.
class DeterministicRNG : public RNG
{
public:
	DeterministicRNG(const std::vector<unsigned char>& pattern, bool succeed = true)
	: m_pattern(pattern), m_succeed(succeed), m_lastRequested(0) {}

	bool generateRandom(ByteString& data, size_t len) override
	{
		m_lastRequested = len;
		if (!m_succeed) return false;
		data.resize(len);
		for (size_t i = 0; i < len; ++i)
		{
			data[i] = m_pattern[i % m_pattern.size()];
		}
		return true;
	}

	size_t lastRequested() const { return m_lastRequested; }

private:
	std::vector<unsigned char> m_pattern;
	bool m_succeed;
	size_t m_lastRequested;
};

// Helper to construct a SymmetricKey with given bit length and (optional) content.
// If bytes is empty, fills with incremental values and sets odd parity where appropriate.
static SymmetricKey makeKey(size_t bitsWithOrWithoutParity, const std::vector<unsigned char>& bytes = {})
{
	SymmetricKey key;
	size_t bytesLen = bitsWithOrWithoutParity / 8;
	ByteString bs;
	bs.resize(bytesLen);

	if (!bytes.empty())
	{
		for (size_t i = 0; i < bytesLen; ++i) bs[i] = bytes[i % bytes.size()];
	}
	else
	{
		for (size_t i = 0; i < bytesLen; ++i) bs[i] = static_cast<unsigned char>(i * 3 + 1);
	}

	// The library accepts both effective and parity-included lengths. We pass bytes as-is.
	bool ok = key.setKeyBits(bs);
	(void)ok; // In case setKeyBits is void in this codebase
	return key;
}

// Utility to set mode on an OSSLDES instance. If the class exposes setCipherMode use it;
// otherwise we exercise via startEncrypt/startDecrypt API setting mode+IV. We guard at compile time.
static void setMode(OSSLDES& des, SymMode::Type mode)
{
#if defined(HAVE_SETCIPHERMODE_METHOD)
	des.setCipherMode(mode);
#else
	// Fallback: try generic SymmetricAlgorithm interface if present
	des.setCipherMode(mode);
#endif
}

#ifdef WITH_OPENSSL
// Map key sizes to expected EVP cipher for a given mode
static const EVP_CIPHER* expectedCipher(SymMode::Type mode, size_t bits)
{
	switch (mode)
	{
		case SymMode::CBC:
			if (bits == 56 || bits == 64) return EVP_des_cbc();
			if (bits == 112 || bits == 128) return EVP_des_ede_cbc();
			if (bits == 168 || bits == 192) return EVP_des_ede3_cbc();
			break;
		case SymMode::ECB:
			if (bits == 56 || bits == 64) return EVP_des_ecb();
			if (bits == 112 || bits == 128) return EVP_des_ede_ecb();
			if (bits == 168 || bits == 192) return EVP_des_ede3_ecb();
			break;
		case SymMode::OFB:
			if (bits == 56 || bits == 64) return EVP_des_ofb();
			if (bits == 112 || bits == 128) return EVP_des_ede_ofb();
			if (bits == 168 || bits == 192) return EVP_des_ede3_ofb();
			break;
		case SymMode::CFB:
			if (bits == 56 || bits == 64) return EVP_des_cfb();
			if (bits == 112 || bits == 128) return EVP_des_ede_cfb();
			if (bits == 168 || bits == 192) return EVP_des_ede3_cfb();
			break;
		default:
			return nullptr;
	}
	return nullptr;
}
#endif

// Fixture for OSSLDES tests
class OSSLDESFixture : public ::testing::Test
{
protected:
	void SetUp() override {}

	OSSLDES des;
};

// getBlockSize
TEST_F(OSSLDESFixture, BlockSizeIsEightBytes)
{
	EXPECT_EQ(des.getBlockSize(), static_cast<size_t>(8));
}

// wrapKey/unwrapKey unsupported
TEST_F(OSSLDESFixture, WrapKeyUnsupportedReturnsFalse)
{
	ByteString in("abcd", 4);
	ByteString out;
	SymmetricKey dummy = makeKey(128);
	bool ok = des.wrapKey(&dummy, SymWrap::Type::Unsupported, in, out);
	EXPECT_FALSE(ok);
	// Should not write output
	EXPECT_EQ(out.size(), static_cast<size_t>(0));
}

TEST_F(OSSLDESFixture, UnwrapKeyUnsupportedReturnsFalse)
{
	ByteString in("abcd", 4);
	ByteString out;
	SymmetricKey dummy = makeKey(128);
	bool ok = des.unwrapKey(&dummy, SymWrap::Type::Unsupported, in, out);
	EXPECT_FALSE(ok);
	EXPECT_EQ(out.size(), static_cast<size_t>(0));
}

// generateKey: requires RNG and non-zero key size; enforces odd parity
TEST_F(OSSLDESFixture, GenerateKeyFailsWithoutRNG)
{
	SymmetricKey k;
	// Set target key length first
	ByteString empty; empty.resize(16); // 128 bits incl. parity
	k.setKeyBits(empty);
	// No RNG
	EXPECT_FALSE(des.generateKey(k, /*rng=*/nullptr));
}

TEST_F(OSSLDESFixture, GenerateKeyFailsWithZeroBitLen)
{
	SymmetricKey k; // no bit length set
	DeterministicRNG rng({0xAA});
	EXPECT_FALSE(des.generateKey(k, &rng));
}

TEST_F(OSSLDESFixture, GenerateKeyUsesEffectiveBitLengthDiv7AndSetsOddParity)
{
	// 3DES 192-bit (incl. parity) => effective bytes = 192/7 rounded down by impl (code calls bitLen/7)
	SymmetricKey k = makeKey(192, std::vector<unsigned char>(24, 0x00));
	DeterministicRNG rng({0x55}); // 0x55 has even parity; after odd parity fix it should become 0x55|1 as needed per table

	// Precondition: ensure k.getBitLen() returns 192 so implementation will compute 192/7 bytes from RNG
	size_t beforeBits = k.getBitLen();
	ASSERT_TRUE(beforeBits == 192 || beforeBits == 168) << "Key should report 192 or effective 168 bits";

	bool ok = des.generateKey(k, &rng);
	EXPECT_TRUE(ok);

	// Validate RNG size requested == bitLen/7 bytes
	EXPECT_EQ(rng.lastRequested(), beforeBits / 7);

	// Validate odd parity on each byte
	const ByteString& kb = k.getKeyBits();
	for (size_t i = 0; i < kb.size(); ++i)
	{
		unsigned char b = kb[i];
		// Check odd parity: count bits set should be odd
		unsigned int ones = __builtin_popcount(static_cast<unsigned int>(b));
		EXPECT_EQ(ones % 2, 1u) << "Byte at " << i << " not odd parity: " << std::hex << (int)b;
	}
}

// getCipher selection for valid sizes/modes
#ifdef WITH_OPENSSL
struct CipherParam {
	SymMode::Type mode;
	size_t bits;
};

class CipherSelectionTest : public ::testing::TestWithParam<CipherParam> {};

TEST_P(CipherSelectionTest, ReturnsExpectedCipherForValidKeyLengthAndMode)
{
	OSSLDES d;
	const auto p = GetParam();

	// Prepare key with specified size
	SymmetricKey k = makeKey(p.bits);
	// The OSSLDES API is expected to use a "setKey" or similar. Use setKey if available.
	// Fallback: set the key on the instance via generic API if the base class provides it.
	ASSERT_TRUE(d.setKey(&k)) << "Failed to set key on OSSLDES";

	setMode(d, p.mode);

	const EVP_CIPHER* got = d.getCipher();
	const EVP_CIPHER* exp = expectedCipher(p.mode, k.getBitLen());

	ASSERT_NE(exp, nullptr) << "Expected cipher nullptr is invalid for provided parameters";
	EXPECT_EQ(got, exp);
}

// Valid param combinations: single DES (56 or 64), 2-key 3DES (112 or 128), 3-key 3DES (168 or 192)
// across modes CBC/ECB/CFB/OFB
INSTANTIATE_TEST_SUITE_P(
	AllModesAndKeySizes,
	CipherSelectionTest,
	::testing::Values(
		CipherParam{SymMode::CBC, 64},
		CipherParam{SymMode::CBC, 128},
		CipherParam{SymMode::CBC, 192},
		CipherParam{SymMode::ECB, 64},
		CipherParam{SymMode::ECB, 128},
		CipherParam{SymMode::ECB, 192},
		CipherParam{SymMode::CFB, 64},
		CipherParam{SymMode::CFB, 128},
		CipherParam{SymMode::CFB, 192},
		CipherParam{SymMode::OFB, 64},
		CipherParam{SymMode::OFB, 128},
		CipherParam{SymMode::OFB, 192}
	)
);
#endif // WITH_OPENSSL

// getCipher invalid key length or mode
TEST_F(OSSLDESFixture, GetCipherReturnsNullWhenNoKeySet)
{
	EXPECT_EQ(des.getCipher(), static_cast<const EVP_CIPHER*>(nullptr));
}

TEST_F(OSSLDESFixture, GetCipherRejectsInvalidKeyLength)
{
	// 40-bit key (invalid)
	SymmetricKey bad = makeKey(40);
	ASSERT_TRUE(des.setKey(&bad));
	setMode(des, SymMode::CBC);
	EXPECT_EQ(des.getCipher(), static_cast<const EVP_CIPHER*>(nullptr));
}

TEST_F(OSSLDESFixture, GetCipherRejectsInvalidMode)
{
	// Using a value outside supported modes if SymMode has Unknown/CTR etc.
	SymmetricKey k = makeKey(128);
	ASSERT_TRUE(des.setKey(&k));

	// If SymMode doesn't have an invalid value, we skip; otherwise set an invalid enum.
	// Here we attempt to set a mode value that is not one of CBC/ECB/CFB/OFB.
	// Use a cast to force an invalid mode integer.
	des.setCipherMode(static_cast<SymMode::Type>(9999));

	EXPECT_EQ(des.getCipher(), static_cast<const EVP_CIPHER*>(nullptr));
}
