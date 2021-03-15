#include <unity.h>

#include "wireguard.h"
#include "wireguard/crypto.h"

// Reference hashes created via Python:
// >>> import hashlib
// >>> ','.join("0x%02x" % x for x in hashlib.blake2s(b'...').digest())
struct
{
	unsigned char *test_input;
	size_t test_input_len;
	union wg_hash expected_hash;
} hash_test_vectors[] = {
    {"",
     0,
     {0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
      0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9}},
    {"abcdefghijklmnopqrstuvwxyz012345",
     32,
     {0xc0, 0xb8, 0x2a, 0x49, 0x81, 0xad, 0x7b, 0xcc, 0xad, 0x87, 0x36, 0x35, 0x40, 0x0a, 0x25, 0x7c,
      0x74, 0x73, 0xa8, 0x05, 0x26, 0xf3, 0xab, 0xa9, 0xe1, 0x31, 0xee, 0x48, 0x72, 0x34, 0x3c, 0x70}},
    {"abcdefghijklmnopqrstuvwxyz0123456ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
     66,
     {0x59, 0x77, 0x9f, 0x4d, 0x53, 0xba, 0xf1, 0x06, 0xde, 0xf2, 0xc3, 0xf6, 0x4c, 0x86, 0xbc, 0x2d,
      0x58, 0x8c, 0xc3, 0x83, 0x21, 0x3c, 0x05, 0xac, 0x0b, 0x06, 0xbe, 0x41, 0xc8, 0x9f, 0x2a, 0xbf}},
};

// Reference MACs created via Python:
// >>> import hashlib
// >>> ','.join("0x%02x" % x for x in hashlib.blake2s(b'...', digest_size=16, key=b'...').digest())
struct
{
	unsigned char *test_input;
	size_t test_input_len;
	unsigned char *test_key;
	union wg_mac expected_mac;
} mac_test_vectors[] = {
    {"",
     0,
     "12345678901234567890123456789012",
     {0x52, 0x93, 0xb8, 0x55, 0x49, 0x00, 0x00, 0x54, 0x6f, 0x3b, 0x98, 0xb8, 0x5b, 0x9e, 0x42, 0x1d}},
    {"abcdefghijklmnopqrstuvwxyz012345",
     32,
     "12345678901234567890123456789012",
     {0xa3, 0x70, 0x84, 0x04, 0xa4, 0xdd, 0xb5, 0x20, 0xef, 0x57, 0xc8, 0xb6, 0xb5, 0x66, 0xaa, 0xa5}},
    {"abcdefghijklmnopqrstuvwxyz0123456ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
     66,
     "12345678901234567890123456789012",
     {0x21, 0x3e, 0xe3, 0xcb, 0x17, 0xe2, 0x1f, 0x8e, 0xc2, 0xe2, 0x95, 0xd3, 0x95, 0x2e, 0x92, 0xc4}},
};

void test_mac_equals(void)
{
	union wg_mac a = {};
	union wg_mac b = {};
	TEST_ASSERT_TRUE(wg_mac_equals(&a, &b));
	a.as_bytes[0] = 1;
	TEST_ASSERT_FALSE(wg_mac_equals(&a, &b));
	a.as_bytes[0] = 0;
	a.as_bytes[15] = 1;
	TEST_ASSERT_FALSE(wg_mac_equals(&a, &b));
	a.as_bytes[15] = 0;
	TEST_ASSERT_TRUE(wg_mac_equals(&a, &b));
}

void test_hash_equals(void)
{
	union wg_hash a = {};
	union wg_hash b = {};
	TEST_ASSERT_TRUE(wg_hash_equals(&a, &b));
	a.as_bytes[0] = 1;
	TEST_ASSERT_FALSE(wg_hash_equals(&a, &b));
	a.as_bytes[0] = 0;
	a.as_bytes[15] = 1;
	TEST_ASSERT_FALSE(wg_hash_equals(&a, &b));
	a.as_bytes[15] = 0;
	TEST_ASSERT_TRUE(wg_hash_equals(&a, &b));
}

void test_key_equals(void)
{
	union wg_key a = {};
	union wg_key b = {};
	TEST_ASSERT_TRUE(wg_key_equals(&a, &b));
	a.as_bytes[0] = 1;
	TEST_ASSERT_FALSE(wg_key_equals(&a, &b));
	a.as_bytes[0] = 0;
	a.as_bytes[31] = 1;
	TEST_ASSERT_FALSE(wg_key_equals(&a, &b));
	a.as_bytes[31] = 0;
	TEST_ASSERT_TRUE(wg_key_equals(&a, &b));
}

void test_hash(void)
{
	for (int i = 0; i < sizeof(hash_test_vectors) / sizeof(hash_test_vectors[0]); i++) {
		union wg_hash actual_hash;
		TEST_ASSERT_EQUAL(0, wg_hash(&actual_hash, hash_test_vectors[i].test_input, hash_test_vectors[i].test_input_len));
		TEST_ASSERT_TRUE(wg_hash_equals(&hash_test_vectors[i].expected_hash, &actual_hash));
	}
}

void test_concat_hash(void)
{
	for (int i = 0; i < sizeof(hash_test_vectors) / sizeof(hash_test_vectors[0]); i++) {
		// Test every possible breaking point
		for (int j = 0; j <= hash_test_vectors[i].test_input_len; j++) {
			union wg_hash actual_hash;
			TEST_ASSERT_EQUAL(0, wg_concat_hash(
						 &actual_hash,
						 &hash_test_vectors[i].test_input[0], j,
						 &hash_test_vectors[i].test_input[j], hash_test_vectors[i].test_input_len - j));
			TEST_ASSERT_TRUE(wg_hash_equals(&hash_test_vectors[i].expected_hash, &actual_hash));
		}
	}
}

void test_mac(void)
{
	for (int i = 0; i < sizeof(mac_test_vectors) / sizeof(mac_test_vectors[0]); i++) {
		union wg_mac actual_mac;
		union wg_key key;
		wg_safe_memcpy(
		    &key, sizeof(key),
		    mac_test_vectors[i].test_key, sizeof(key));
		TEST_ASSERT_EQUAL(0, wg_mac(&actual_mac, &key, mac_test_vectors[i].test_input, mac_test_vectors[i].test_input_len));
		TEST_ASSERT_TRUE(wg_mac_equals(&mac_test_vectors[i].expected_mac, &actual_mac));
	}
}

void test_base64(void)
{
	union wg_key reference_key = {"Have a lot of fun."};
	char reference_base64[] = "SGF2ZSBhIGxvdCBvZiBmdW4uAAAAAAAAAAAAAAAAAAA=";

	char actual_base64[128] = {};
	TEST_ASSERT_EQUAL(0, wg_key_to_base64(actual_base64, sizeof(actual_base64), &reference_key));
	TEST_ASSERT_EQUAL_STRING(reference_base64, actual_base64);

	union wg_key actual_key = {};
	TEST_ASSERT_EQUAL(0, wg_base64_to_key(&actual_key, reference_base64, strlen(reference_base64)));
	TEST_ASSERT_EQUAL_CHAR_ARRAY(reference_key.as_bytes, actual_key.as_bytes, sizeof(reference_key.as_bytes));
}

int main(int argc, char **argv)
{
	if (0 != wg_init()) {
		return 1;
	}

	UNITY_BEGIN();
	RUN_TEST(test_mac_equals);
	RUN_TEST(test_hash_equals);
	RUN_TEST(test_hash);
	RUN_TEST(test_concat_hash);
	RUN_TEST(test_mac);
	RUN_TEST(test_base64);
	UNITY_END();

	return 0;
}
