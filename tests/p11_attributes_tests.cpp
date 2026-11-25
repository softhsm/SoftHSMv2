#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include <cstring>
#include <string>
#include <cassert>

// Prefer including the real headers if available; fall back to local relative includes.
#include "P11Attributes.h"

// Minimal fake implementations to exercise logic without real crypto
// If the real classes exist, these fakes can be compiled out by guarding with macros.
// For this testing file, we implement only methods used by the attribute logic.

class FakeToken : public Token {
public:
    FakeToken(): soLoggedIn(false), encFail(false), decFail(false) {}
    bool soLoggedIn;
    bool encFail;
    bool decFail;

    bool isSOLoggedIn() override { return soLoggedIn; }

    bool encrypt(const ByteString& in, ByteString& out) override {
        if (encFail) return false;
        out = in; // no-op encryption for tests
        return true;
    }
    bool decrypt(const ByteString& in, ByteString& out) override {
        if (decFail) return false;
        out = in; // no-op decryption for tests
        return true;
    }
};

class FakeOSObject : public OSObject {
public:
    std::map<CK_ATTRIBUTE_TYPE, OSAttribute> store;

    bool attributeExists(CK_ATTRIBUTE_TYPE type) override {
        return store.find(type) != store.end();
    }
    bool setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& val) override {
        store[type] = val;
        return true;
    }
    OSAttribute getAttribute(CK_ATTRIBUTE_TYPE type) override {
        return store[type];
    }

    // Convenience typed getters mirrored from production API
    bool getBooleanValue(CK_ATTRIBUTE_TYPE type, bool def) override {
        auto it = store.find(type);
        if (it == store.end() || !it->second.isBooleanAttribute()) return def;
        return it->second.getBooleanValue();
    }
    unsigned long getUnsignedLongValue(CK_ATTRIBUTE_TYPE type, unsigned long def) override {
        auto it = store.find(type);
        if (it == store.end() || !it->second.isUnsignedLongAttribute()) return def;
        return it->second.getUnsignedLongValue();
    }
    ByteString getByteStringValue(CK_ATTRIBUTE_TYPE type) override {
        auto it = store.find(type);
        if (it == store.end() || !it->second.isByteStringAttribute()) return ByteString();
        return it->second.getByteStringValue();
    }
};

static void expect_true(bool cond, const char* msg) { if (!cond) { fprintf(stderr, "FAILED: %s\n", msg); assert(cond); } }
static void expect_false(bool cond, const char* msg) { expect_true(!cond, msg); }
static void expect_eq_ulong(unsigned long a, unsigned long b, const char* msg) { if (a!=b) { fprintf(stderr, "FAILED: %s (%lu != %lu)\n", msg, a, b); assert(a==b);} }
static void expect_eq_bytes(const ByteString& a, const ByteString& b, const char* msg) { if (!(a==b)) { fprintf(stderr, "FAILED: %s (sizes %zu vs %zu)\n", msg, a.size(), b.size()); assert(a==b);} }

static void test_defaults_and_flags() {
    FakeOSObject obj;
    P11Attribute base(&obj);

    // Modifiable default true if absent
    expect_true(base.isModifiable(), "CKA_MODIFIABLE default true");

    // Sensitive default false if absent
    expect_false(base.isSensitive(), "CKA_SENSITIVE default false");

    // Extractable default true if absent
    expect_true(base.isExtractable(), "CKA_EXTRACTABLE default true");

    // Trusted default false if absent
    expect_false(base.isTrusted(), "CKA_TRUSTED default false");

    // Set explicit values and re-check
    obj.setAttribute(CKA_MODIFIABLE, OSAttribute(false));
    obj.setAttribute(CKA_SENSITIVE, OSAttribute(true));
    obj.setAttribute(CKA_EXTRACTABLE, OSAttribute(false));
    obj.setAttribute(CKA_TRUSTED, OSAttribute(true));

    expect_false(base.isModifiable(), "CKA_MODIFIABLE false");
    expect_true(base.isSensitive(), "CKA_SENSITIVE true");
    expect_false(base.isExtractable(), "CKA_EXTRACTABLE false");
    expect_true(base.isTrusted(), "CKA_TRUSTED true");
}

static void test_retrieve_size_and_buffer_rules() {
    FakeOSObject obj;
    FakeToken tok;

    // Prepare a variable-sized attribute (ByteString) under type CKA_LABEL
    P11Attribute base(&obj);
    // Force attribute type to CKA_LABEL for this test
    // Note: We mimic a derived class by writing directly to osobject store.
    ByteString val(reinterpret_cast<const unsigned char*>("hello"), 5);
    obj.setAttribute(CKA_LABEL, OSAttribute(val));

    // Emulate base operating on type CKA_LABEL
    // We need pValue==NULL -> returns size, then with exact buffer, then too small.
    CK_ULONG reqLen = 0;
    base.type = CKA_LABEL; // accessing protected; if not accessible, tests should instead instantiate P11AttrLabel
    CK_RV rv = base.retrieve(&tok, /*isPrivate=*/false, NULL_PTR, &reqLen);
    expect_eq_ulong(rv, CKR_OK, "retrieve size query ok");
    expect_eq_ulong(reqLen, 5, "retrieve size equals 5");

    unsigned char buf[5];
    CK_ULONG len = sizeof(buf);
    rv = base.retrieve(&tok, false, buf, &len);
    expect_eq_ulong(rv, CKR_OK, "retrieve copy ok");
    expect_eq_ulong(len, 5, "retrieve len 5");
    expect_true(std::memcmp(buf, "hello", 5) == 0, "retrieve copied bytes");

    unsigned char small[4];
    CK_ULONG slen = sizeof(small);
    rv = base.retrieve(&tok, false, small, &slen);
    expect_eq_ulong(rv, CKR_BUFFER_TOO_SMALL, "retrieve buffer too small");
    expect_eq_ulong(slen, CK_UNAVAILABLE_INFORMATION, "retrieve len set to CK_UNAVAILABLE_INFORMATION");
}

static void test_retrieve_sensitive_extractable_gate() {
    FakeOSObject obj;
    FakeToken tok;

    // Mark attribute with ck7 check and object as sensitive or unextractable
    P11Attribute base(&obj);
    base.type = CKA_VALUE; // variable-size
    base.checks = P11Attribute::ck7; // simulate check gating

    obj.setAttribute(CKA_SENSITIVE, OSAttribute(true));
    obj.setAttribute(CKA_VALUE, OSAttribute(ByteString(reinterpret_cast<const unsigned char*>("secret"), 6)));

    CK_ULONG outLen = 0;
    CK_RV rv = base.retrieve(&tok, /*isPrivate=*/false, NULL_PTR, &outLen);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_SENSITIVE, "retrieve blocked by sensitivity");
    expect_eq_ulong(outLen, CK_UNAVAILABLE_INFORMATION, "len unavailable when sensitive");

    // Now set sensitive false but extractable false
    obj.setAttribute(CKA_SENSITIVE, OSAttribute(false));
    obj.setAttribute(CKA_EXTRACTABLE, OSAttribute(false));
    rv = base.retrieve(&tok, false, NULL_PTR, &outLen);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_SENSITIVE, "retrieve blocked by non-extractable");
    expect_eq_ulong(outLen, CK_UNAVAILABLE_INFORMATION, "len unavailable when non-extractable");
}

static void test_update_readonly_rules_and_checks() {
    FakeOSObject obj;
    FakeToken tok;

    // Base attribute acting on CKA_LABEL (variable)
    P11Attribute base(&obj);
    base.type = CKA_LABEL;

    // Not modifiable and op is SET => READ_ONLY
    obj.setAttribute(CKA_MODIFIABLE, OSAttribute(false));
    unsigned char name[] = "x";
    CK_RV rv = base.update(&tok, false, name, 1, OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "update blocked when CKA_MODIFIABLE false");

    // Modifiable true; set ck2 prohibiting on CREATE
    obj.setAttribute(CKA_MODIFIABLE, OSAttribute(true));
    base.checks = P11Attribute::ck2;
    rv = base.update(&tok, false, name, 1, OBJECT_OP_CREATE);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "ck2 prohibits in CREATE");

    // ck4 prohibits in GENERATE
    base.checks = P11Attribute::ck4;
    rv = base.update(&tok, false, name, 1, OBJECT_OP_GENERATE);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "ck4 prohibits in GENERATE");

    // ck6 prohibits in UNWRAP
    base.checks = P11Attribute::ck6;
    rv = base.update(&tok, false, name, 1, OBJECT_OP_UNWRAP);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "ck6 prohibits in UNWRAP");

    // ck8 allows modification via SET/COPY
    base.checks = P11Attribute::ck8;
    rv = base.update(&tok, false, name, 1, OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_OK, "ck8 allows SET");
    expect_true(obj.getByteStringValue(CKA_LABEL) == ByteString(name, 1), "label updated");

    // Trusted certificate cannot be modified (outside of create/generate)
    P11Attribute base2(&obj);
    base2.type = CKA_LABEL;
    obj.setAttribute(CKA_TRUSTED, OSAttribute(true));
    obj.setAttribute(CKA_CLASS, OSAttribute((unsigned long)CKO_CERTIFICATE));
    rv = base2.update(&tok, false, name, 1, OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "trusted certificate not modifiable");
}

static void test_attr_trusted_so_only() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrTrusted attr(&obj);

    // Default false
    expect_false(obj.getBooleanValue(CKA_TRUSTED, false), "trusted default false");

    // Try set to true without SO
    CK_BBOOL t = CK_TRUE;
    CK_RV rv = attr.updateAttr(&tok, false, &t, sizeof(t), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "CKA_TRUSTED true requires SO");

    // With SO
    tok.soLoggedIn = true;
    rv = attr.updateAttr(&tok, false, &t, sizeof(t), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_OK, "CKA_TRUSTED set by SO");
    expect_true(obj.getBooleanValue(CKA_TRUSTED, false), "trusted now true");

    // Set to false allowed without SO
    CK_BBOOL f = CK_FALSE;
    tok.soLoggedIn = false;
    rv = attr.updateAttr(&tok, false, &f, sizeof(f), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_OK, "CKA_TRUSTED reset to false allowed");
    expect_false(obj.getBooleanValue(CKA_TRUSTED, true), "trusted false");
}

static void test_attr_sensitive_rules() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrSensitive attr(&obj);

    // Initially false
    expect_false(obj.getBooleanValue(CKA_SENSITIVE, true), "sensitive default false");

    // Set true during GENERATE also sets ALWAYS_SENSITIVE
    CK_BBOOL t = CK_TRUE;
    CK_RV rv = attr.updateAttr(&tok, false, &t, sizeof(t), OBJECT_OP_GENERATE);
    expect_eq_ulong(rv, CKR_OK, "set sensitive true generate");
    expect_true(obj.getBooleanValue(CKA_SENSITIVE, false), "sensitive true");
    expect_true(obj.getBooleanValue(CKA_ALWAYS_SENSITIVE, false), "always sensitive true");

    // Once true, SET/COPY cannot modify
    rv = attr.updateAttr(&tok, false, &t, sizeof(t), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "cannot modify sensitive via SET once true");

    // Set false allowed only if value is false and will clear ALWAYS_SENSITIVE
    CK_BBOOL f = CK_FALSE;
    // Temporarily clear via GENERATE to test clearing path
    obj.setAttribute(CKA_SENSITIVE, OSAttribute(true));
    rv = attr.updateAttr(&tok, false, &f, sizeof(f), OBJECT_OP_GENERATE);
    expect_eq_ulong(rv, CKR_OK, "set sensitive false generate");
    expect_false(obj.getBooleanValue(CKA_SENSITIVE, true), "sensitive false");
    expect_false(obj.getBooleanValue(CKA_ALWAYS_SENSITIVE, true), "always sensitive false");
}

static void test_attr_extractable_rules() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrExtractable attr(&obj);

    // Default false in code
    expect_false(obj.getBooleanValue(CKA_EXTRACTABLE, true), "extractable default false");

    // SET or COPY cannot change from false -> should be READ_ONLY
    CK_BBOOL t = CK_TRUE;
    CK_RV rv = attr.updateAttr(&tok, false, &t, sizeof(t), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_ATTRIBUTE_READ_ONLY, "extractable cannot be set to true via SET if currently false");

    // GENERATE can set it
    rv = attr.updateAttr(&tok, false, &t, sizeof(t), OBJECT_OP_GENERATE);
    expect_eq_ulong(rv, CKR_OK, "extractable set true via GENERATE");
    expect_true(obj.getBooleanValue(CKA_EXTRACTABLE, false), "extractable now true");
    expect_false(obj.getBooleanValue(CKA_NEVER_EXTRACTABLE, true), "NEVER_EXTRACTABLE cleared");
}

static void test_attr_always_authenticate_private_only() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrAlwaysAuthenticate attr(&obj);

    // Setting true for non-private object should be inconsistent
    CK_BBOOL t = CK_TRUE;
    CK_RV rv = attr.updateAttr(&tok, /*isPrivate=*/false, &t, sizeof(t), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_TEMPLATE_INCONSISTENT, "AlwaysAuthenticate requires private object");

    // For private object allowed
    rv = attr.updateAttr(&tok, /*isPrivate=*/true, &t, sizeof(t), OBJECT_OP_SET);
    expect_eq_ulong(rv, CKR_OK, "AlwaysAuthenticate set for private");
    expect_true(obj.getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false), "AlwaysAuthenticate true");
}

static void test_attr_value_sets_lengths_on_create() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrValue attr(&obj);

    // Ensure CKA_VALUE_LEN and CKA_VALUE_BITS present to be set
    obj.setAttribute(CKA_VALUE_LEN, OSAttribute((unsigned long)0));
    obj.setAttribute(CKA_VALUE_BITS, OSAttribute((unsigned long)0));

    const unsigned char data[] = {0x01,0x02,0x03,0x04,0x05};
    CK_RV rv = attr.updateAttr(&tok, /*isPrivate=*/false, (void*)data, sizeof(data), OBJECT_OP_CREATE);
    expect_eq_ulong(rv, CKR_OK, "value set ok");

    expect_eq_ulong(obj.getUnsignedLongValue(CKA_VALUE_LEN, 0), (unsigned long)sizeof(data), "VALUE_LEN set");
    // ByteString::bits() returns size*8; we expect 40
    expect_eq_ulong(obj.getUnsignedLongValue(CKA_VALUE_BITS, 0), (unsigned long)sizeof(data)*8, "VALUE_BITS set");
}

static void test_attr_modulus_sets_bits_on_create() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrModulus attr(&obj);

    obj.setAttribute(CKA_MODULUS_BITS, OSAttribute((unsigned long)0));

    const unsigned char nbytes[] = {0x01,0x02,0x03};
    CK_RV rv = attr.updateAttr(&tok, false, (void*)nbytes, sizeof(nbytes), OBJECT_OP_CREATE);
    expect_eq_ulong(rv, CKR_OK, "modulus set ok");
    expect_eq_ulong(obj.getUnsignedLongValue(CKA_MODULUS_BITS, 0), (unsigned long)sizeof(nbytes)*8, "MODULUS_BITS set");
}

static void test_attr_prime_sets_bits_on_create() {
    FakeOSObject obj;
    FakeToken tok;
    P11AttrPrime attr(&obj);

    obj.setAttribute(CKA_PRIME_BITS, OSAttribute((unsigned long)0));

    const unsigned char pbytes[] = {0xFF,0x00,0xAA,0x55};
    CK_RV rv = attr.updateAttr(&tok, false, (void*)pbytes, sizeof(pbytes), OBJECT_OP_CREATE);
    expect_eq_ulong(rv, CKR_OK, "prime set ok");
    expect_eq_ulong(obj.getUnsignedLongValue(CKA_PRIME_BITS, 0), (unsigned long)sizeof(pbytes)*8, "PRIME_BITS set");
}

int main() {
    test_defaults_and_flags();
    test_retrieve_size_and_buffer_rules();
    test_retrieve_sensitive_extractable_gate();
    test_update_readonly_rules_and_checks();
    test_attr_trusted_so_only();
    test_attr_sensitive_rules();
    test_attr_extractable_rules();
    test_attr_always_authenticate_private_only();
    test_attr_value_sets_lengths_on_create();
    test_attr_modulus_sets_bits_on_create();
    test_attr_prime_sets_bits_on_create();
    return 0;
}