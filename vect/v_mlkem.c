/**
 * @file v_mlkem.c
 * @brief Reads ML-KEM JSON test vectors and performs Known Answer Tests (KATs).
 *
 * This script depends on the Jansson library for JSON parsing.
 * You will need to install Jansson (e.g., on macOS: `brew install jansson`).
 *
 * To compile on macOS (M1, with Homebrew Jansson):
 * gcc -o v_mlkem vect/v_mlkem.c implementations/mlkem/mlkem.c -I. -std=c99 -Wall -I/opt/homebrew/include -L/opt/homebrew/lib -ljansson
 *
 * To run:
 * ./v_mlkem ../vectors/mlkem_kat_example.json
 * (Replace with your actual ML-KEM KAT JSON file path)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include "../implementations/mlkem.h"  // ML-KEM implementation header

// Use maximum possible sizes for buffers based on ML-KEM_1024
#define MAX_PK_LEN MLKEM_1024_PK_LEN
#define MAX_SK_LEN MLKEM_1024_SK_LEN
#define MAX_CT_LEN MLKEM_1024_CT_LEN
#define MAX_SS_LEN MLKEM_1024_SS_LEN // This is 32 bytes for all ML-KEM variants

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
 * @param byte_array Output buffer for the byte array. If NULL, only calculates length.
 * @param max_len Maximum allowed length for the byte array.
 * @return The length of the converted byte array on success, -1 on error.
 */
static int hex_to_bytes(const char *hex_str, uint8_t *byte_array, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Error: Hex string has odd length.\n");
        return -1;
    }

    size_t byte_len = len / 2;
    if (byte_array != NULL && byte_len > max_len) {
        fprintf(stderr, "Error: Buffer too small. Required: %zu, Max: %zu\n", byte_len, max_len);
        return -1;
    }

    if (byte_array != NULL) {
        for (size_t i = 0; i < byte_len; i++) {
            int high = hex_char_to_int(hex_str[i*2]);
            int low = hex_char_to_int(hex_str[i*2+1]);

            if (high == -1 || low == -1) {
                fprintf(stderr, "Error: Invalid hex character at position %zu\n", i*2);
                return -1;
            }
            byte_array[i] = (uint8_t)((high << 4) | low);
        }
    }

    return (int)byte_len;
}

/**
 * @brief Maps parameter set string to mlkem_param_t enum.
 * @param param_str The parameter set string from JSON.
 * @return The corresponding mlkem_param_t enum value, or -1 if invalid.
 */
static int get_mlkem_param_enum(const char *param_str) {
    if (strcmp(param_str, "ML-KEM-512") == 0) return MLKEM_512;
    if (strcmp(param_str, "ML-KEM-768") == 0) return MLKEM_768;
    if (strcmp(param_str, "ML-KEM-1024") == 0) return MLKEM_1024;
    return -1; // Invalid parameter
}

/**
 * @brief Runs a single MLKEMTest (KeyGen and Decapsulation) test vector.
 * @param test_case_obj JSON object for the current test case.
 * @param param ML-KEM parameter set for this group.
 * @return 1 if the test case passed, 0 otherwise.
 */
static int run_mlkem_keygen_decaps_test_vector(
    json_t *test_case_obj,
    mlkem_param_t param
) {
    json_t *tc_id_json = json_object_get(test_case_obj, "tcId");
    json_t *seed_json = json_object_get(test_case_obj, "seed");
    json_t *ek_expected_json = json_object_get(test_case_obj, "ek");
    json_t *c_json = json_object_get(test_case_obj, "c");
    json_t *K_expected_json = json_object_get(test_case_obj, "K");
    json_t *result_json = json_object_get(test_case_obj, "result");

    KAT_ASSERT(json_is_integer(tc_id_json), "tcId is not an integer");
    KAT_ASSERT(json_is_string(seed_json), "seed is not a string");
    KAT_ASSERT(json_is_string(ek_expected_json), "ek is not a string");
    KAT_ASSERT(json_is_string(c_json), "c is not a string");
    KAT_ASSERT(json_is_string(K_expected_json), "K is not a string");
    KAT_ASSERT(json_is_string(result_json), "result is not a string");

    int tc_id = json_integer_value(tc_id_json);
    const char *seed_hex = json_string_value(seed_json);
    const char *ek_expected_hex = json_string_value(ek_expected_json);
    const char *c_hex = json_string_value(c_json);
    const char *K_expected_hex = json_string_value(K_expected_json);
    const char *expected_result_str = json_string_value(result_json);

    uint8_t seed_bytes[MAX_SS_LEN * 2]; // Assuming seed can be up to 64 bytes (d || z)
    size_t seed_len;
    int conv_seed_res = hex_to_bytes(seed_hex, seed_bytes, sizeof(seed_bytes));
    KAT_ASSERT(conv_seed_res >= 0, "Seed hex conversion failed (tcId %d)", tc_id);
    seed_len = (size_t)conv_seed_res;

    uint8_t ek_expected_bytes[MAX_PK_LEN];
    size_t ek_expected_len;
    int conv_ek_res = hex_to_bytes(ek_expected_hex, ek_expected_bytes, MAX_PK_LEN);
    KAT_ASSERT(conv_ek_res >= 0, "EK hex conversion failed (tcId %d)", tc_id);
    ek_expected_len = (size_t)conv_ek_res;

    uint8_t c_bytes[MAX_CT_LEN];
    size_t c_len;
    int conv_c_res = hex_to_bytes(c_hex, c_bytes, MAX_CT_LEN);
    KAT_ASSERT(conv_c_res >= 0, "C hex conversion failed (tcId %d)", tc_id);
    c_len = (size_t)conv_c_res;

    uint8_t K_expected_bytes[MAX_SS_LEN];
    size_t K_expected_len;
    int conv_K_res = hex_to_bytes(K_expected_hex, K_expected_bytes, MAX_SS_LEN);
    KAT_ASSERT(conv_K_res >= 0, "K hex conversion failed (tcId %d)", tc_id);
    K_expected_len = (size_t)conv_K_res;

    // --- Key Generation and Public Key Comparison ---
    uint8_t *pk_generated = NULL;
    uint8_t *sk_generated = NULL;
    
    printf("  Running MLKEMTest TC #%d (KeyGen & Decaps)...\n", tc_id);

    // In a real implementation, the seed would be used for deterministic keygen.
    // For now, we call the stub which allocates dummy keys.
    int keygen_res = mlkem_keygen(param, &pk_generated, &sk_generated);
    KAT_ASSERT(keygen_res == MLKEM_OK, "Keygen failed (tcId %d, Error: %d)", tc_id, keygen_res);
    KAT_ASSERT(pk_generated != NULL && sk_generated != NULL, "Keygen returned NULL keys (tcId %d)", tc_id);

    // Get generated PK length (assuming it's consistent with param)
    size_t pk_generated_len;
    switch (param) {
        case MLKEM_512: pk_generated_len = MLKEM_512_PK_LEN; break;
        case MLKEM_768: pk_generated_len = MLKEM_768_PK_LEN; break;
        case MLKEM_1024: pk_generated_len = MLKEM_1024_PK_LEN; break;
        default: pk_generated_len = 0; break;
    }

    // Compare generated public key with expected public key
    KAT_ASSERT(pk_generated_len == ek_expected_len,
               "Generated PK length mismatch (tcId %d). Expected: %zu, Got: %zu",
               tc_id, ek_expected_len, pk_generated_len);
    KAT_ASSERT(memcmp(pk_generated, ek_expected_bytes, ek_expected_len) == 0,
               "Generated PK mismatch (tcId %d)", tc_id);

    // --- Decapsulation ---
    uint8_t K_decapsulated[MAX_SS_LEN];
    // Use MAX_SS_LEN for the ss_len argument
    int decaps_res = mlkem_decaps(sk_generated, c_bytes, c_len, K_decapsulated, MAX_SS_LEN);

    int test_passed = 1; // Assume pass until a failure is found

    if (strcmp(expected_result_str, "valid") == 0 || strcmp(expected_result_str, "acceptable") == 0) {
        if (decaps_res == MLKEM_OK) {
            // Compare decapsulated shared secret with expected
            if (memcmp(K_decapsulated, K_expected_bytes, K_expected_len) != 0) {
                fprintf(stderr, "KAT FAIL: Decapsulated K mismatch (tcId %d)\n", tc_id);
                test_passed = 0;
            }
        } else {
            fprintf(stderr, "KAT FAIL: Decapsulation failed for valid case (tcId %d, Error: %d)\n", tc_id, decaps_res);
            test_passed = 0;
        }
    } else if (strcmp(expected_result_str, "invalid") == 0) {
        if (decaps_res == MLKEM_OK) {
            fprintf(stderr, "KAT FAIL: Decapsulation succeeded for invalid case (tcId %d)\n", tc_id);
            test_passed = 0;
        } else {
            // Expected to fail, so any non-OK result is good.
            // Specific error code (MLKEM_DECAP_FAIL or MLKEM_INVALID_CIPHERTEXT) might be checked in a real test.
        }
    } else {
        fprintf(stderr, "KAT FAIL: Unknown expected result type '%s' (tcId %d)\n", expected_result_str, tc_id);
        test_passed = 0;
    }

    mlkem_free_keys(pk_generated, sk_generated); // Free allocated keys

    if (test_passed) {
        printf("  MLKEMTest TC #%d: PASSED\n", tc_id);
        return 1;
    } else {
        return 0; // Test case failed
    }
}

/**
 * @brief Runs a single MLKEMEncapsTest (Encapsulation) test vector.
 * @param test_case_obj JSON object for the current test case.
 * @param param ML-KEM parameter set for this group.
 * @return 1 if the test case passed, 0 otherwise.
 */
static int run_mlkem_encaps_test_vector(
    json_t *test_case_obj,
    mlkem_param_t param
) {
    json_t *tc_id_json = json_object_get(test_case_obj, "tcId");
    json_t *ek_json = json_object_get(test_case_obj, "ek");
    // json_t *m_json = json_object_get(test_case_obj, "m"); // 'm' is for internal randomness, not directly used by mlkem_encaps in mlkem.h
    json_t *c_expected_json = json_object_get(test_case_obj, "c");
    json_t *K_expected_json = json_object_get(test_case_obj, "K");
    json_t *result_json = json_object_get(test_case_obj, "result");

    KAT_ASSERT(json_is_integer(tc_id_json), "tcId is not an integer");
    KAT_ASSERT(json_is_string(ek_json), "ek is not a string");
    KAT_ASSERT(json_is_string(c_expected_json), "c is not a string");
    KAT_ASSERT(json_is_string(K_expected_json), "K is not a string");
    KAT_ASSERT(json_is_string(result_json), "result is not a string");

    int tc_id = json_integer_value(tc_id_json);
    const char *ek_hex = json_string_value(ek_json);
    const char *c_expected_hex = json_string_value(c_expected_json);
    const char *K_expected_hex = json_string_value(K_expected_json);
    const char *expected_result_str = json_string_value(result_json);

    uint8_t ek_bytes[MAX_PK_LEN];
    size_t ek_len;
    int conv_ek_res = hex_to_bytes(ek_hex, ek_bytes, MAX_PK_LEN);
    KAT_ASSERT(conv_ek_res >= 0, "EK hex conversion failed (tcId %d)", tc_id);
    ek_len = (size_t)conv_ek_res;

    uint8_t c_expected_bytes[MAX_CT_LEN];
    size_t c_expected_len;
    int conv_c_res = hex_to_bytes(c_expected_hex, c_expected_bytes, MAX_CT_LEN);
    KAT_ASSERT(conv_c_res >= 0, "C hex conversion failed (tcId %d)", tc_id);
    c_expected_len = (size_t)conv_c_res;

    uint8_t K_expected_bytes[MAX_SS_LEN];
    size_t K_expected_len;
    int conv_K_res = hex_to_bytes(K_expected_hex, K_expected_bytes, MAX_SS_LEN);
    KAT_ASSERT(conv_K_res >= 0, "K hex conversion failed (tcId %d)", tc_id);
    K_expected_len = (size_t)conv_K_res;

    // --- Encapsulation ---
    uint8_t c_generated[MAX_CT_LEN];
    size_t c_generated_len = MAX_CT_LEN; // Initialize with max capacity
    uint8_t K_generated[MAX_SS_LEN];

    printf("  Running MLKEMEncapsTest TC #%d (Encaps)...\n", tc_id);

    // Use MAX_SS_LEN for the ss_len argument
    int encaps_res = mlkem_encaps(ek_bytes, c_generated, &c_generated_len, K_generated, MAX_SS_LEN);

    int test_passed = 1; // Assume pass until a failure is found

    if (strcmp(expected_result_str, "valid") == 0 || strcmp(expected_result_str, "acceptable") == 0) {
        if (encaps_res == MLKEM_OK) {
            // Compare generated ciphertext with expected
            if (c_generated_len != c_expected_len || memcmp(c_generated, c_expected_bytes, c_expected_len) != 0) {
                fprintf(stderr, "KAT FAIL: Generated C mismatch (tcId %d). Expected len: %zu, Got len: %zu\n",
                        tc_id, c_expected_len, c_generated_len);
                test_passed = 0;
            }
            // Compare generated shared secret with expected
            if (memcmp(K_generated, K_expected_bytes, K_expected_len) != 0) {
                fprintf(stderr, "KAT FAIL: Generated K mismatch (tcId %d)\n", tc_id);
                test_passed = 0;
            }
        } else {
            fprintf(stderr, "KAT FAIL: Encapsulation failed for valid case (tcId %d, Error: %d)\n", tc_id, encaps_res);
            test_passed = 0;
        }
    } else if (strcmp(expected_result_str, "invalid") == 0) {
        if (encaps_res == MLKEM_OK) {
            fprintf(stderr, "KAT FAIL: Encapsulation succeeded for invalid case (tcId %d)\n", tc_id);
            test_passed = 0;
        } else {
            // Expected to fail, so any non-OK result is good.
        }
    } else {
        fprintf(stderr, "KAT FAIL: Unknown expected result type '%s' (tcId %d)\n", expected_result_str, tc_id);
        test_passed = 0;
    }

    if (test_passed) {
        printf("  MLKEMEncapsTest TC #%d: PASSED\n", tc_id);
        return 1;
    } else {
        return 0; // Test case failed
    }
}

/**
 * @brief Processes an MLKEMTestGroup from the JSON.
 * @param test_group_json The JSON object representing the test group.
 * @return The number of failed tests in this group.
 */
static int process_mlkem_test_group(json_t *test_group_json) {
    json_t *parameter_set_json, *tests_json, *test_vector_json;
    const char *parameter_set_str;
    mlkem_param_t current_param;
    int failures = 0;

    parameter_set_json = json_object_get(test_group_json, "parameterSet");
    parameter_set_str = json_string_value(parameter_set_json);
    KAT_ASSERT(parameter_set_str != NULL, "Missing parameterSet in MLKEMTestGroup");

    current_param = get_mlkem_param_enum(parameter_set_str);
    KAT_ASSERT(current_param != -1, "Invalid parameterSet string '%s'", parameter_set_str);

    tests_json = json_object_get(test_group_json, "tests");
    if (!json_is_array(tests_json)) {
        fprintf(stderr, "Error: 'tests' is not an array in MLKEMTestGroup.\n");
        return 1;
    }

    size_t index;
    json_array_foreach(tests_json, index, test_vector_json) {
        if (run_mlkem_keygen_decaps_test_vector(test_vector_json, current_param) != 1) {
            failures++;
        }
    }
    return failures;
}

/**
 * @brief Processes an MLKEMEncapsTestGroup from the JSON.
 * @param test_group_json The JSON object representing the test group.
 * @return The number of failed tests in this group.
 */
static int process_mlkem_encaps_test_group(json_t *test_group_json) {
    json_t *parameter_set_json, *tests_json, *test_vector_json;
    const char *parameter_set_str;
    mlkem_param_t current_param;
    int failures = 0;

    parameter_set_json = json_object_get(test_group_json, "parameterSet");
    parameter_set_str = json_string_value(parameter_set_json);
    KAT_ASSERT(parameter_set_str != NULL, "Missing parameterSet in MLKEMEncapsTestGroup");

    current_param = get_mlkem_param_enum(parameter_set_str);
    KAT_ASSERT(current_param != -1, "Invalid parameterSet string '%s'", parameter_set_str);

    tests_json = json_object_get(test_group_json, "tests");
    if (!json_is_array(tests_json)) {
        fprintf(stderr, "Error: 'tests' is not an array in MLKEMEncapsTestGroup.\n");
        return 1;
    }

    size_t index;
    json_array_foreach(tests_json, index, test_vector_json) {
        if (run_mlkem_encaps_test_vector(test_vector_json, current_param) != 1) {
            failures++;
        }
    }
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

        if (strcmp(type, "MLKEMTest") == 0) {
            printf("  Running MLKEMTest Group %zu...\n", index + 1);
            total_failures += process_mlkem_test_group(test_group_json);
        } else if (strcmp(type, "MLKEMEncapsTest") == 0) {
            printf("  Running MLKEMEncapsTest Group %zu...\n", index + 1);
            total_failures += process_mlkem_encaps_test_group(test_group_json);
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
        fprintf(stderr, "Usage: %s <path_to_mlkem_kat.json>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Starting ML-KEM KAT Tests\n");
    printf("=========================\n");

    int overall_failures = 0;

    // Process the single KAT file provided as an argument
    overall_failures += process_kat_file(argv[1]);

    printf("\n===================================================\n");
    if (overall_failures == 0) {
        printf("All KAT tests processed successfully for %s!\n", argv[1]);
        printf("NOTE: Actual cryptographic validation depends on a complete mlkem.c implementation.\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Total KAT failures: %d for %s.\n", overall_failures, argv[1]);
        fprintf(stderr, "NOTE: Failures are expected if mlkem.c contains stub implementations.\n");
        return EXIT_FAILURE;
    }
}
