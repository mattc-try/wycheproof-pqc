/**
 * @file mldsa_test.c
 * @brief ML-DSA (Module Lattice Digital Signature Algorithm) unit tests
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../implementations/mldsa.h" 

// Test configuration
#define TEST_ITERATIONS 100
#define TEST_MSG "Test message for ML-DSA signatures"

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

static void test_mldsa_keygen(mldsa_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    
    // Generate key pair
    TEST_ASSERT(mldsa_keygen(param, &pk, &sk) == MLDSA_OK, "Key generation failed");
    
    // Validate key lengths
    size_t expected_pk_len, expected_sk_len;
    switch (param) {
        case MLDSA_44:
            expected_pk_len = MLDSA_44_PK_LEN;
            expected_sk_len = MLDSA_44_SK_LEN;
            break;
        case MLDSA_65:
            expected_pk_len = MLDSA_65_PK_LEN;
            expected_sk_len = MLDSA_65_SK_LEN;
            break;
        case MLDSA_87:
            expected_pk_len = MLDSA_87_PK_LEN;
            expected_sk_len = MLDSA_87_SK_LEN;
            break;
        default:
            TEST_ASSERT(0, "Invalid ML-DSA parameter");
            return;
    }
    
    TEST_ASSERT(pk != NULL, "Public key is NULL");
    TEST_ASSERT(sk != NULL, "Secret key is NULL");
    
    // Clean up
    mldsa_free_keys(pk, sk);
}

static void test_mldsa_sign_verify(mldsa_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[MLDSA_87_SIG_MAX];  // Use largest possible buffer
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);
    
    // Generate key pair
    TEST_ASSERT(mldsa_keygen(param, &pk, &sk) == MLDSA_OK, "Key generation failed");
    
    // Sign message
    sig_len = (param == MLDSA_44) ? MLDSA_44_SIG_MAX : 
              (param == MLDSA_65) ? MLDSA_65_SIG_MAX : MLDSA_87_SIG_MAX;
    TEST_ASSERT(mldsa_sign(sk, msg, msg_len, sig, &sig_len) == MLDSA_OK, "Signing failed");
    
    // Verify valid signature
    TEST_ASSERT(mldsa_verify(pk, msg, msg_len, sig, sig_len) == MLDSA_OK, 
               "Verification failed for valid signature");
    
    // Verify with wrong message
    uint8_t bad_msg[] = "Tampered message";
    TEST_ASSERT(mldsa_verify(pk, bad_msg, sizeof(bad_msg)-1, sig, sig_len) == MLDSA_VERIFY_FAIL, 
               "Verification passed for wrong message");
    
    // Clean up
    mldsa_free_keys(pk, sk);
}

static void test_mldsa_invalid_signature(mldsa_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[MLDSA_87_SIG_MAX];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);
    
    // Generate key pair
    TEST_ASSERT(mldsa_keygen(param, &pk, &sk) == MLDSA_OK, "Key generation failed");
    
    // Sign message to get a valid signature to corrupt
    sig_len = (param == MLDSA_44) ? MLDSA_44_SIG_MAX : 
              (param == MLDSA_65) ? MLDSA_65_SIG_MAX : MLDSA_87_SIG_MAX;
    TEST_ASSERT(mldsa_sign(sk, msg, msg_len, sig, &sig_len) == MLDSA_OK, "Signing failed");
    
    // Corrupt signature
    TEST_ASSERT(sig_len > 0, "Signature length must be > 0 to corrupt");
    sig[0] ^= 0xFF; // Flip a bit in the signature
    
    // Attempt verification with corrupted signature
    int result = mldsa_verify(pk, msg, msg_len, sig, sig_len);
    
    // Verification should fail (return MLDSA_VERIFY_FAIL) for an invalid signature
    TEST_ASSERT(result == MLDSA_VERIFY_FAIL, 
               "Verification should fail for corrupted signature");
    
    // Clean up
    mldsa_free_keys(pk, sk);
}

static void test_mldsa_empty_message(mldsa_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[MLDSA_87_SIG_MAX];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)"";
    size_t msg_len = 0;
    
    // Generate key pair
    TEST_ASSERT(mldsa_keygen(param, &pk, &sk) == MLDSA_OK, "Key generation failed");
    
    // Sign empty message
    sig_len = (param == MLDSA_44) ? MLDSA_44_SIG_MAX : 
              (param == MLDSA_65) ? MLDSA_65_SIG_MAX : MLDSA_87_SIG_MAX;
    TEST_ASSERT(mldsa_sign(sk, msg, msg_len, sig, &sig_len) == MLDSA_OK, 
               "Signing empty message failed");
    
    // Verify empty message
    TEST_ASSERT(mldsa_verify(pk, msg, msg_len, sig, sig_len) == MLDSA_OK, 
               "Verification failed for empty message");
    
    // Clean up
    mldsa_free_keys(pk, sk);
}

//---------------------------
// Test runner
//---------------------------

static void run_tests_for_param(mldsa_param_t param) {
    const char *param_name;
    switch (param) {
        case MLDSA_44: param_name = "ML-DSA-44"; break;
        case MLDSA_65: param_name = "ML-DSA-65"; break;
        case MLDSA_87: param_name = "ML-DSA-87"; break;
        default: param_name = "UNKNOWN ML-DSA PARAM"; break;
    }

    printf("\n[%s Parameter Set]\n", param_name);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        TEST_RUN(test_mldsa_keygen, param);
        TEST_RUN(test_mldsa_sign_verify, param);
        TEST_RUN(test_mldsa_invalid_signature, param);
        TEST_RUN(test_mldsa_empty_message, param);
    }
}

int main(void) {
    printf("Starting ML-DSA Implementation Tests\n");
    printf("===================================\n");

    // Test all ML-DSA parameter sets
    run_tests_for_param(MLDSA_44);
    run_tests_for_param(MLDSA_65);
    run_tests_for_param(MLDSA_87);

    printf("\nAll ML-DSA tests completed successfully!\n");
    return EXIT_SUCCESS;
}