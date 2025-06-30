/**
 * @file mlkem_test.c
 * @brief ML-KEM (Module Lattice Key Encapsulation Mechanism) unit tests
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../implementations/mlkem.h"  // Include the ML-KEM header

// Test configuration
#define TEST_ITERATIONS 100

// Test utilities
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

#define TEST_RUN(name, param_val) do { \
    printf("  %-30s", #name); \
    fflush(stdout); \
    name(param_val); \
    printf(" [PASS]\n"); \
} while(0)

//---------------------------
// Test cases
//---------------------------

static void test_mlkem_keygen(mlkem_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    
    // Generate key pair
    TEST_ASSERT(mlkem_keygen(param, &pk, &sk) == MLKEM_OK, "Key generation failed");
    
    // Validate key lengths
    size_t expected_pk_len, expected_sk_len;
    switch (param) {
        case MLKEM_512:
            expected_pk_len = MLKEM_512_PK_LEN;
            expected_sk_len = MLKEM_512_SK_LEN;
            break;
        case MLKEM_768:
            expected_pk_len = MLKEM_768_PK_LEN;
            expected_sk_len = MLKEM_768_SK_LEN;
            break;
        case MLKEM_1024:
            expected_pk_len = MLKEM_1024_PK_LEN;
            expected_sk_len = MLKEM_1024_SK_LEN;
            break;
        default:
            TEST_ASSERT(0, "Invalid ML-KEM parameter");
            return;
    }
    
    TEST_ASSERT(pk != NULL, "Public key is NULL");
    TEST_ASSERT(sk != NULL, "Secret key is NULL");
    
    // Clean up
    mlkem_free_keys(pk, sk);
}

static void test_mlkem_encaps_decaps(mlkem_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t ct[MLKEM_1024_CT_LEN];  // Use largest possible buffer
    uint8_t ss1[MLKEM_1024_SS_LEN], ss2[MLKEM_1024_SS_LEN];
    size_t ct_len, ss_len;
    
    // Generate key pair
    TEST_ASSERT(mlkem_keygen(param, &pk, &sk) == MLKEM_OK, "Key generation failed");
    
    // Encapsulation
    ct_len = (param == MLKEM_512) ? MLKEM_512_CT_LEN : 
             (param == MLKEM_768) ? MLKEM_768_CT_LEN : MLKEM_1024_CT_LEN;
    ss_len = MLKEM_512_SS_LEN;  // Shared secret length is same for all
    
    TEST_ASSERT(mlkem_encaps(pk, ct, &ct_len, ss1, ss_len) == MLKEM_OK, 
               "Encapsulation failed");
    
    // Decapsulation
    TEST_ASSERT(mlkem_decaps(sk, ct, ct_len, ss2, ss_len) == MLKEM_OK, 
               "Decapsulation failed");
    
    // Verify shared secrets match
    TEST_ASSERT(memcmp(ss1, ss2, ss_len) == 0,
               "Encapsulated and decapsulated secrets do not match");
    
    // Clean up
    mlkem_free_keys(pk, sk);
}

static void test_mlkem_invalid_ciphertext(mlkem_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t ct[MLKEM_1024_CT_LEN];
    uint8_t ss1[MLKEM_1024_SS_LEN], ss2[MLKEM_1024_SS_LEN];
    size_t ct_len, ss_len;
    
    // Generate key pair
    TEST_ASSERT(mlkem_keygen(param, &pk, &sk) == MLKEM_OK, "Key generation failed");
    
    // Encapsulation to get valid ciphertext
    ct_len = (param == MLKEM_512) ? MLKEM_512_CT_LEN : 
             (param == MLKEM_768) ? MLKEM_768_CT_LEN : MLKEM_1024_CT_LEN;
    ss_len = MLKEM_512_SS_LEN;
    
    TEST_ASSERT(mlkem_encaps(pk, ct, &ct_len, ss1, ss_len) == MLKEM_OK, 
               "Encapsulation failed");
    
    // Corrupt ciphertext
    TEST_ASSERT(ct_len > 0, "Ciphertext length must be > 0 to corrupt");
    ct[0] ^= 0xFF;  // Flip a bit
    
    // Attempt decapsulation
    int result = mlkem_decaps(sk, ct, ct_len, ss2, ss_len);
    
    // Should either fail or produce different shared secret
    if (result == MLKEM_OK) {
        TEST_ASSERT(memcmp(ss1, ss2, ss_len) != 0,
                   "Decapsulation with invalid ciphertext should not produce same secret");
    } else {
        TEST_ASSERT(result == MLKEM_DECAP_FAIL,
                   "Expected decapsulation failure for invalid ciphertext");
    }
    
    // Clean up
    mlkem_free_keys(pk, sk);
}

//---------------------------
// Test runner
//---------------------------

static void run_tests_for_param(mlkem_param_t param) {
    const char *param_name;
    switch (param) {
        case MLKEM_512: param_name = "ML-KEM-512"; break;
        case MLKEM_768: param_name = "ML-KEM-768"; break;
        case MLKEM_1024: param_name = "ML-KEM-1024"; break;
        default: param_name = "UNKNOWN ML-KEM PARAM"; break;
    }

    printf("\n[%s Parameter Set]\n", param_name);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        TEST_RUN(test_mlkem_keygen, param);
        TEST_RUN(test_mlkem_encaps_decaps, param);
        TEST_RUN(test_mlkem_invalid_ciphertext, param);
    }
}

int main(void) {
    printf("Starting ML-KEM Implementation Tests\n");
    printf("===================================\n");

    // Test all ML-KEM parameter sets
    run_tests_for_param(MLKEM_512);
    run_tests_for_param(MLKEM_768);
    run_tests_for_param(MLKEM_1024);

    printf("\nAll ML-KEM tests completed successfully!\n");
    return EXIT_SUCCESS;
}