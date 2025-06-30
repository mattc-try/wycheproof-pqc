/**
 * @file falcon_kat_runner.c
 * @brief Reads Falcon JSON test vectors and performs Known Answer Tests (KATs).
 * 
 * This script depends on the Jansson library for JSON parsing.
 * You will need to install Jansson (e.g., on macOS: `brew install jansson`).
 * 
 * To compile:
 * gcc -std=c11 -Wall -Wextra falcon_kat_runner.c hex_to_bytes.c -o falcon_kat_runner -ljansson -L../tested-implementations/falcon -lfalcon
 * 
 * To run:
 * ./falcon_kat_runner ../vectors/falcon512_rsp_sign_kat.json
 * ./falcon_kat_runner ../vectors/falcon1024_rsp_sign_kat.json
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include "../implementations/falcon.h"  // Falcon implementation header

// Buffer sizes for Falcon parameters
#define FALCON512_PK_LEN 897
#define FALCON512_SK_LEN 1281
#define FALCON512_SIG_MAX 690

#define FALCON1024_PK_LEN 1793
#define FALCON1024_SK_LEN 2305
#define FALCON1024_SIG_MAX 1330

#define MAX_MSG_LEN 256   // Max message length for KAT tests

// Use maximum possible sizes for buffers
#define MAX_PK_LEN FALCON1024_PK_LEN
#define MAX_SK_LEN FALCON1024_SK_LEN
#define MAX_SIG_LEN FALCON1024_SIG_MAX

// Test assertion macro
#define KAT_ASSERT(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "KAT FAIL: %s:%d: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        return 0; \
    } \
} while(0)

/**
 * @brief Converts a single hexadecimal character to its integer value.
 */
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/**
 * @brief Converts a hexadecimal string to a byte array.
 */
int hex_to_bytes(const char *hex_str, uint8_t *byte_array, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Error: Hex string has odd length.\n");
        return -1;
    }

    size_t byte_len = len / 2;
    if (byte_len > max_len) {
        fprintf(stderr, "Error: Buffer too small. Required: %zu, Max: %zu\n", byte_len, max_len);
        return -1;
    }

    for (size_t i = 0; i < byte_len; i++) {
        int high = hex_char_to_int(hex_str[i*2]);
        int low = hex_char_to_int(hex_str[i*2+1]);

        if (high == -1 || low == -1) {
            fprintf(stderr, "Error: Invalid hex character at position %zu\n", i*2);
            return -1;
        }
        byte_array[i] = (uint8_t)((high << 4) | low);
    }

    return byte_len;
}

/**
 * @brief Runs a single Falcon KAT test case.
 */
static int run_falcon_sign_kat_test_case(
    json_t *test_case_obj,
    const uint8_t *pk_bytes, size_t pk_len,
    const uint8_t *sk_bytes, size_t sk_len
) {
    // Extract test case data
    json_t *tc_id_json = json_object_get(test_case_obj, "tcId");
    json_t *msg_json = json_object_get(test_case_obj, "msg");
    json_t *sig_json = json_object_get(test_case_obj, "sig");
    json_t *result_json = json_object_get(test_case_obj, "result");

    KAT_ASSERT(json_is_integer(tc_id_json), "tcId is not an integer");
    KAT_ASSERT(json_is_string(msg_json), "msg is not a string");
    KAT_ASSERT(json_is_string(sig_json), "sig is not a string");
    KAT_ASSERT(json_is_string(result_json), "result is not a string");

    int tc_id = json_integer_value(tc_id_json);
    const char *msg_hex = json_string_value(msg_json);
    const char *sig_expected_hex = json_string_value(sig_json);
    const char *result_str = json_string_value(result_json);

    uint8_t msg_bytes[MAX_MSG_LEN];
    uint8_t sig_expected_bytes[MAX_SIG_LEN];
    uint8_t sig_generated_bytes[MAX_SIG_LEN];
    size_t msg_len, sig_expected_len, sig_generated_len;

    // Convert hex strings to bytes
    int conv_msg = hex_to_bytes(msg_hex, msg_bytes, MAX_MSG_LEN);
    KAT_ASSERT(conv_msg >= 0, "Msg hex conversion failed (tcId %d)", tc_id);
    msg_len = conv_msg;

    int conv_sig = hex_to_bytes(sig_expected_hex, sig_expected_bytes, MAX_SIG_LEN);
    KAT_ASSERT(conv_sig >= 0, "Sig hex conversion failed (tcId %d)", tc_id);
    sig_expected_len = conv_sig;

    printf("  Running KAT Test Case %d...\n", tc_id);

    // 1. Test signing
    sig_generated_len = MAX_SIG_LEN;
    int sign_res = falcon_sign(sk_bytes, msg_bytes, msg_len, 
                              sig_generated_bytes, &sig_generated_len);
    KAT_ASSERT(sign_res == 0, "Signing failed (tcId %d)", tc_id);
    
    // Compare generated signature with expected
    KAT_ASSERT(sig_generated_len == sig_expected_len, 
               "Signature length mismatch (tcId %d). Expected: %zu, Got: %zu", 
               tc_id, sig_expected_len, sig_generated_len);
               
    KAT_ASSERT(memcmp(sig_generated_bytes, sig_expected_bytes, sig_expected_len) == 0,
               "Signature mismatch (tcId %d)", tc_id);

    // 2. Test verification
    int verify_res = falcon_verify(pk_bytes, msg_bytes, msg_len, 
                                  sig_expected_bytes, sig_expected_len);
    int expected_valid = (strcmp(result_str, "valid") == 0);

    if (expected_valid) {
        KAT_ASSERT(verify_res == 0, 
                   "Verification failed for valid signature (tcId %d)", tc_id);
    } else {
        KAT_ASSERT(verify_res != 0, 
                   "Verification passed for invalid signature (tcId %d)", tc_id);
    }

    printf("  KAT Test Case %d: PASSED\n", tc_id);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_falcon_rsp_sign_kat.json>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load JSON file
    json_error_t error;
    json_t *root = json_load_file(argv[1], 0, &error);
    if (!root) {
        fprintf(stderr, "JSON error: %s (line %d, col %d)\n", 
                error.text, error.line, error.column);
        return EXIT_FAILURE;
    }

    // Determine Falcon parameters
    json_t *alg_json = json_object_get(root, "algorithm");
    KAT_ASSERT(json_is_string(alg_json), "Missing algorithm string");
    const char *algorithm_name = json_string_value(alg_json);

    int is_falcon512 = 0;
    if (strcmp(algorithm_name, "Falcon-512") == 0) {
        is_falcon512 = 1;
    } else if (strcmp(algorithm_name, "Falcon-1024") == 0) {
        is_falcon512 = 0;
    } else {
        fprintf(stderr, "Unsupported algorithm: %s\n", algorithm_name);
        json_decref(root);
        return EXIT_FAILURE;
    }

    json_t *test_groups = json_object_get(root, "testGroups");
    KAT_ASSERT(json_is_array(test_groups), "Missing testGroups array");

    int total_tests = 0;
    int passed_tests = 0;

    printf("Starting Falcon KAT Tests: %s\n", algorithm_name);
    printf("===================================================\n");

    // Process each test group
    size_t group_idx;
    json_t *test_group;
    json_array_foreach(test_groups, group_idx, test_group) {
        json_t *group_pk_json = json_object_get(test_group, "publicKey");
        json_t *group_sk_json = json_object_get(test_group, "privateKey");
        json_t *tests_array = json_object_get(test_group, "tests");

        KAT_ASSERT(json_is_string(group_pk_json), "Group publicKey missing");
        KAT_ASSERT(json_is_string(group_sk_json), "Group privateKey missing");
        KAT_ASSERT(json_is_array(tests_array), "Missing tests array");

        const char *pk_hex = json_string_value(group_pk_json);
        const char *sk_hex = json_string_value(group_sk_json);

        // Convert group keys
        uint8_t pk_bytes[MAX_PK_LEN];
        uint8_t sk_bytes[MAX_SK_LEN];
        
        int pk_len = hex_to_bytes(pk_hex, pk_bytes, MAX_PK_LEN);
        int sk_len = hex_to_bytes(sk_hex, sk_bytes, MAX_SK_LEN);
        
        KAT_ASSERT(pk_len > 0, "Public key conversion failed");
        KAT_ASSERT(sk_len > 0, "Private key conversion failed");

        // Validate key lengths
        if (is_falcon512) {
            KAT_ASSERT(pk_len == FALCON512_PK_LEN, 
                       "Invalid Falcon-512 public key length: %d", pk_len);
            KAT_ASSERT(sk_len == FALCON512_SK_LEN, 
                       "Invalid Falcon-512 private key length: %d", sk_len);
        } else {
            KAT_ASSERT(pk_len == FALCON1024_PK_LEN, 
                       "Invalid Falcon-1024 public key length: %d", pk_len);
            KAT_ASSERT(sk_len == FALCON1024_SK_LEN, 
                       "Invalid Falcon-1024 private key length: %d", sk_len);
        }

        // Process each test case
        size_t test_idx;
        json_t *test_case;
        json_array_foreach(tests_array, test_idx, test_case) {
            total_tests++;
            passed_tests += run_falcon_sign_kat_test_case(
                test_case, pk_bytes, pk_len, sk_bytes, sk_len
            );
        }
    }

    json_decref(root);

    printf("\n===================================================\n");
    printf("Falcon KAT Summary: Passed %d/%d tests\n", passed_tests, total_tests);
    
    if (passed_tests == total_tests) {
        printf("All tests passed successfully!\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "%d tests failed!\n", total_tests - passed_tests);
        return EXIT_FAILURE;
    }
}