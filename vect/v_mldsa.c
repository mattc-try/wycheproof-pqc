/**
 * @file v_mldsa.c
 * @brief Reads ML-DSA JSON test vectors and performs Known Answer Tests (KATs).
 *
 * This script depends on the Jansson library for JSON parsing.
 * You will need to install Jansson (e.g., on macOS: `brew install jansson`).
 *
 * To compile on macOS (M1, with Homebrew Jansson):
 * gcc -o v_mldsa vect/v_mldsa.c implementations/mldsa/mldsa.c -I. -std=c99 -Wall -I/opt/homebrew/include -L/opt/homebrew/lib -ljansson
 *
 * To run:
 * ./v_mldsa ../vectors/mldsa_sign_kat_example.json
 * ./v_mldsa ../vectors/mldsa_verify_kat_example.json
 * (Replace with your actual ML-DSA KAT JSON file paths)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include "../implementations/mldsa.h"  // ML-DSA implementation header

// Use maximum possible sizes for buffers based on ML-DSA_87
#define MAX_PK_LEN MLDSA_87_PK_LEN
#define MAX_SK_LEN MLDSA_87_SK_LEN
#define MAX_SIG_LEN MLDSA_87_SIG_MAX
#define MAX_MSG_LEN 256   // Max message length for KAT tests (adjust as needed)

// Test assertion macro
#define KAT_ASSERT(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "KAT FAIL: %s:%d: " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        return 0; /* Return 0 to indicate test case failure */ \
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
 * @param hex_str The input hexadecimal string.
 * @param byte_array Output buffer for the byte array.
 * @param max_len Maximum allowed length for the byte array.
 * @return The length of the converted byte array on success, -1 on error.
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

    return (int)byte_len; // Cast to int as per function signature
}

/**
 * @brief Runs a single ML-DSA signing test vector.
 * @param test_case_obj JSON object for the current test case.
 * @param sk_bytes Private key bytes for the test group.
 * @param sk_len Length of private key bytes.
 * @return 1 if the test case passed, 0 otherwise.
 */
static int run_mldsa_sign_test_vector(
    json_t *test_case_obj,
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
    int conv_msg_res = hex_to_bytes(msg_hex, msg_bytes, MAX_MSG_LEN);
    KAT_ASSERT(conv_msg_res >= 0, "Msg hex conversion failed (tcId %d)", tc_id);
    msg_len = (size_t)conv_msg_res;

    int conv_sig_res = hex_to_bytes(sig_expected_hex, sig_expected_bytes, MAX_SIG_LEN);
    KAT_ASSERT(conv_sig_res >= 0, "Sig hex conversion failed (tcId %d)", tc_id);
    sig_expected_len = (size_t)conv_sig_res;

    printf("  Running Sign KAT Test Case %d...\n", tc_id);

    // 1. Test signing
    sig_generated_len = MAX_SIG_LEN; // Initialize with max capacity
    int sign_res = mldsa_sign(sk_bytes, msg_bytes, msg_len,
                              sig_generated_bytes, &sig_generated_len);
    KAT_ASSERT(sign_res == MLDSA_OK, "Signing failed (tcId %d, Error: %d)", tc_id, sign_res);
    
    // Compare generated signature with expected
    KAT_ASSERT(sig_generated_len == sig_expected_len,
               "Signature length mismatch (tcId %d). Expected: %zu, Got: %zu",
               tc_id, sig_expected_len, sig_generated_len);
               
    KAT_ASSERT(memcmp(sig_generated_bytes, sig_expected_bytes, sig_expected_len) == 0,
               "Signature mismatch (tcId %d)", tc_id);

    printf("  Sign KAT Test Case %d: PASSED\n", tc_id);
    return 1; // Test case passed
}

/**
 * @brief Runs a single ML-DSA verification test vector.
 * @param test_case_obj JSON object for the current test case.
 * @param pk_bytes Public key bytes for the test group.
 * @param pk_len Length of public key bytes.
 * @return 1 if the test case passed, 0 otherwise.
 */
static int run_mldsa_verify_test_vector(
    json_t *test_case_obj,
    const uint8_t *pk_bytes, size_t pk_len
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
    const char *sig_hex = json_string_value(sig_json);
    const char *result_str = json_string_value(result_json);

    uint8_t msg_bytes[MAX_MSG_LEN];
    uint8_t sig_bytes[MAX_SIG_LEN];
    size_t msg_len, sig_len;

    // Convert hex strings to bytes
    int conv_msg_res = hex_to_bytes(msg_hex, msg_bytes, MAX_MSG_LEN);
    KAT_ASSERT(conv_msg_res >= 0, "Msg hex conversion failed (tcId %d)", tc_id);
    msg_len = (size_t)conv_msg_res;

    int conv_sig_res = hex_to_bytes(sig_hex, sig_bytes, MAX_SIG_LEN);
    KAT_ASSERT(conv_sig_res >= 0, "Sig hex conversion failed (tcId %d)", tc_id);
    sig_len = (size_t)conv_sig_res;

    printf("  Running Verify KAT Test Case %d...\n", tc_id);

    // Test verification
    int verify_res = mldsa_verify(pk_bytes, msg_bytes, msg_len,
                                  sig_bytes, sig_len);
    int expected_valid = (strcmp(result_str, "valid") == 0);

    if (expected_valid) {
        KAT_ASSERT(verify_res == MLDSA_OK,
                   "Verification failed for valid signature (tcId %d, Error: %d)", tc_id, verify_res);
    } else {
        KAT_ASSERT(verify_res == MLDSA_VERIFY_FAIL || verify_res == MLDSA_INVALID_SIG,
                   "Verification passed for invalid signature (tcId %d, Result: %d)", tc_id, verify_res);
    }

    printf("  Verify KAT Test Case %d: PASSED\n", tc_id);
    return 1; // Test case passed
}

/**
 * @brief Processes an MlDsaSignTestGroup from the JSON.
 * @param test_group_json The JSON object representing the test group.
 * @param current_param The ML-DSA parameter set for this group.
 * @return The number of failed tests in this group.
 */
static int process_mldsa_sign_test_group(json_t *test_group_json, mldsa_param_t current_param) {
    json_t *private_key_json, *tests_json, *test_vector_json;
    const char *private_key_hex;
    uint8_t *sk_bytes = NULL;
    size_t sk_len = 0;
    int failures = 0;

    private_key_json = json_object_get(test_group_json, "privateKey");
    private_key_hex = json_string_value(private_key_json);

    if (private_key_hex == NULL) {
        fprintf(stderr, "Error: Missing privateKey in MlDsaSignTestGroup.\n");
        return 1;
    }
    
    int conv_sk_res = hex_to_bytes(private_key_hex, NULL, 0); // Get length first
    if (conv_sk_res < 0) {
        fprintf(stderr, "Error: Invalid privateKey hex string in MlDsaSignTestGroup.\n");
        return 1;
    }
    sk_len = (size_t)conv_sk_res;

    sk_bytes = (uint8_t*)malloc(sk_len);
    if (sk_bytes == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for private key.\n");
        return 1;
    }
    hex_to_bytes(private_key_hex, sk_bytes, sk_len); // Convert to bytes

    // Validate key length based on the determined parameter set
    size_t expected_sk_len;
    switch (current_param) {
        case MLDSA_44: expected_sk_len = MLDSA_44_SK_LEN; break;
        case MLDSA_65: expected_sk_len = MLDSA_65_SK_LEN; break;
        case MLDSA_87: expected_sk_len = MLDSA_87_SK_LEN; break;
        default: expected_sk_len = 0; break; // Should not happen
    }
    if (sk_len != expected_sk_len) {
        fprintf(stderr, "KAT FAIL: Private key length mismatch for %s. Expected: %zu, Got: %zu\n",
                json_string_value(json_object_get(test_group_json, "type")), expected_sk_len, sk_len);
        free(sk_bytes);
        return 1;
    }


    tests_json = json_object_get(test_group_json, "tests");
    if (!json_is_array(tests_json)) {
        fprintf(stderr, "Error: 'tests' is not an array in MlDsaSignTestGroup.\n");
        free(sk_bytes);
        return 1;
    }

    size_t index;
    json_array_foreach(tests_json, index, test_vector_json) {
        if (run_mldsa_sign_test_vector(test_vector_json, sk_bytes, sk_len) != 1) {
            failures++;
        }
    }

    free(sk_bytes);
    return failures;
}

/**
 * @brief Processes an MlDsaVerifyTestGroup from the JSON.
 * @param test_group_json The JSON object representing the test group.
 * @param current_param The ML-DSA parameter set for this group.
 * @return The number of failed tests in this group.
 */
static int process_mldsa_verify_test_group(json_t *test_group_json, mldsa_param_t current_param) {
    json_t *public_key_json, *tests_json, *test_vector_json;
    const char *public_key_hex;
    uint8_t *pk_bytes = NULL;
    size_t pk_len = 0;
    int failures = 0;

    // IMPORTANT: Schema uses "public_key" (snake_case)
    public_key_json = json_object_get(test_group_json, "public_key");
    public_key_hex = json_string_value(public_key_json);

    if (public_key_hex == NULL) {
        fprintf(stderr, "Error: Missing public_key in MlDsaVerifyTestGroup.\n");
        return 1;
    }

    int conv_pk_res = hex_to_bytes(public_key_hex, NULL, 0); // Get length first
    if (conv_pk_res < 0) {
        fprintf(stderr, "Error: Invalid public_key hex string in MlDsaVerifyTestGroup.\n");
        return 1;
    }
    pk_len = (size_t)conv_pk_res;

    pk_bytes = (uint8_t*)malloc(pk_len);
    if (pk_bytes == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for public key.\n");
        return 1;
    }
    hex_to_bytes(public_key_hex, pk_bytes, pk_len); // Convert to bytes

    // Validate key length based on the determined parameter set
    size_t expected_pk_len;
    switch (current_param) {
        case MLDSA_44: expected_pk_len = MLDSA_44_PK_LEN; break;
        case MLDSA_65: expected_pk_len = MLDSA_65_PK_LEN; break;
        case MLDSA_87: expected_pk_len = MLDSA_87_PK_LEN; break;
        default: expected_pk_len = 0; break; // Should not happen
    }
    if (pk_len != expected_pk_len) {
        fprintf(stderr, "KAT FAIL: Public key length mismatch for %s. Expected: %zu, Got: %zu\n",
                json_string_value(json_object_get(test_group_json, "type")), expected_pk_len, pk_len);
        free(pk_bytes);
        return 1;
    }

    tests_json = json_object_get(test_group_json, "tests");
    if (!json_is_array(tests_json)) {
        fprintf(stderr, "Error: 'tests' is not an array in MlDsaVerifyTestGroup.\n");
        free(pk_bytes);
        return 1;
    }

    size_t index;
    json_array_foreach(tests_json, index, test_vector_json) {
        if (run_mldsa_verify_test_vector(test_vector_json, pk_bytes, pk_len) != 1) {
            failures++;
        }
    }

    free(pk_bytes);
    return failures;
}


/**
 * @brief Processes a single KAT JSON file.
 * @param filepath The path to the JSON file.
 * @return The total number of failed tests in the file.
 */
static int process_kat_file(const char *filepath) {
    json_t *root;
    json_error_t error;
    int total_failures = 0;

    printf("\n--- Processing KAT file: %s ---\n", filepath);

    root = json_load_file(filepath, 0, &error);
    if (!root) {
        fprintf(stderr, "Error: Failed to load JSON file %s: %s (line %d, col %d)\n",
                filepath, error.text, error.line, error.column);
        return 1; // Indicate failure to process file
    }

    json_t *alg_json = json_object_get(root, "algorithm");
    if (!json_is_string(alg_json)) {
        fprintf(stderr, "Error: 'algorithm' is missing or not a string in %s.\n", filepath);
        json_decref(root);
        return 1;
    }
    const char *algorithm_name = json_string_value(alg_json);

    mldsa_param_t current_param;
    if (strcmp(algorithm_name, "ML-DSA-44") == 0) {
        current_param = MLDSA_44;
    } else if (strcmp(algorithm_name, "ML-DSA-65") == 0) {
        current_param = MLDSA_65;
    } else if (strcmp(algorithm_name, "ML-DSA-87") == 0) {
        current_param = MLDSA_87;
    } else {
        fprintf(stderr, "Error: Unsupported algorithm '%s' in %s.\n", algorithm_name, filepath);
        json_decref(root);
        return 1;
    }


    json_t *test_groups_json = json_object_get(root, "testGroups");
    if (!json_is_array(test_groups_json)) {
        fprintf(stderr, "Error: 'testGroups' is not an array or missing in %s.\n", filepath);
        json_decref(root);
        return 1;
    }

    size_t index;
    json_t *test_group_json;
    json_array_foreach(test_groups_json, index, test_group_json) {
        json_t *type_json = json_object_get(test_group_json, "type");
        const char *type = json_string_value(type_json);

        if (type == NULL) {
            fprintf(stderr, "Error: Test group 'type' is missing or not a string.\n");
            total_failures++;
            continue;
        }

        if (strcmp(type, "MlDsaSign") == 0) {
            printf("  Running MlDsaSign Test Group %zu...\n", index + 1);
            total_failures += process_mldsa_sign_test_group(test_group_json, current_param);
        } else if (strcmp(type, "MlDsaVerify") == 0) {
            printf("  Running MlDsaVerify Test Group %zu...\n", index + 1);
            total_failures += process_mldsa_verify_test_group(test_group_json, current_param);
        } else {
            fprintf(stderr, "Warning: Unknown test group type '%s' in %s. Skipping.\n", type, filepath);
        }
    }

    json_decref(root);
    return total_failures;
}

// --- Main Function ---

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_mldsa_kat.json>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Starting ML-DSA KAT Tests\n");
    printf("=========================\n");

    int overall_failures = 0;

    // Process the single KAT file provided as an argument
    overall_failures += process_kat_file(argv[1]);

    printf("\n===================================================\n");
    if (overall_failures == 0) {
        printf("All KAT tests processed successfully for %s!\n", argv[1]);
        printf("NOTE: Actual cryptographic validation depends on a complete mldsa.c implementation.\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Total KAT failures: %d for %s.\n", overall_failures, argv[1]);
        fprintf(stderr, "NOTE: Failures are expected if mldsa.c contains stub implementations.\n");
        return EXIT_FAILURE;
    }
}
