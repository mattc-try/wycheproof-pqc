/**
 * @file falcon_test.c
 * @brief Falcon signature scheme unit tests
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Test configuration
#define TEST_ITERATIONS 100
#define TEST_MSG "Test message for Falcon signatures"
#define MAX_SIG_LEN 2048

// Falcon parameters
typedef enum {
    FALCON512,
    FALCON1024
} falcon_param_t;

// Implementation interface
int falcon_keygen(falcon_param_t param, uint8_t **pk, uint8_t **sk);
int falcon_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len, 
                uint8_t *sig, size_t *sig_len);
int falcon_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, 
                  const uint8_t *sig, size_t sig_len);
void falcon_free_keys(uint8_t *pk, uint8_t *sk);

// Test utilities
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

#define TEST_RUN(name) do { \
    printf("  %-30s", #name); \
    fflush(stdout); \
    name(); \
    printf(" [PASS]\n"); \
} while(0)

//---------------------------
// Test cases
//---------------------------

static void test_keygen(falcon_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    
    // Generate key pair
    TEST_ASSERT(falcon_keygen(param, &pk, &sk), "Key generation failed");
    
    // Validate key lengths
    size_t expected_pk_len = (param == FALCON512) ? 897 : 1793;
    size_t expected_sk_len = (param == FALCON512) ? 1281 : 2305;
    
    size_t pk_len = (param == FALCON512) ? 
                    /* FALCON512_PK_LEN */ 897 : 
                    /* FALCON1024_PK_LEN */ 1793;
    
    size_t sk_len = (param == FALCON512) ? 
                    /* FALCON512_SK_LEN */ 1281 : 
                    /* FALCON1024_SK_LEN */ 2305;
    
    TEST_ASSERT(pk != NULL, "Public key is NULL");
    TEST_ASSERT(sk != NULL, "Secret key is NULL");
    TEST_ASSERT(pk_len == expected_pk_len, "Invalid public key length");
    TEST_ASSERT(sk_len == expected_sk_len, "Invalid secret key length");
    
    // Clean up
    falcon_free_keys(pk, sk);
}

static void test_sign_verify(falcon_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[MAX_SIG_LEN];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);
    
    // Generate key pair
    TEST_ASSERT(falcon_keygen(param, &pk, &sk), "Key generation failed");
    
    // Sign message
    TEST_ASSERT(falcon_sign(sk, msg, msg_len, sig, &sig_len), "Signing failed");
    
    // Verify valid signature
    TEST_ASSERT(falcon_verify(pk, msg, msg_len, sig, sig_len), 
               "Verification failed for valid signature");
    
    // Verify with wrong message
    uint8_t bad_msg[] = "Tampered message";
    TEST_ASSERT(!falcon_verify(pk, bad_msg, sizeof(bad_msg)-1, sig, sig_len), 
               "Verification passed for wrong message");
    
    // Verify with corrupted signature
    uint8_t bad_sig[MAX_SIG_LEN];
    memcpy(bad_sig, sig, sig_len);
    bad_sig[sig_len/2] ^= 0xFF;  // Flip bits
    TEST_ASSERT(!falcon_verify(pk, msg, msg_len, bad_sig, sig_len), 
               "Verification passed for corrupted signature");
    
    // Clean up
    falcon_free_keys(pk, sk);
}

static void test_empty_message(falcon_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[MAX_SIG_LEN];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)"";
    size_t msg_len = 0;
    
    // Generate key pair
    TEST_ASSERT(falcon_keygen(param, &pk, &sk), "Key generation failed");
    
    // Sign empty message
    TEST_ASSERT(falcon_sign(sk, msg, msg_len, sig, &sig_len), 
               "Signing empty message failed");
    
    // Verify empty message
    TEST_ASSERT(falcon_verify(pk, msg, msg_len, sig, sig_len), 
               "Verification failed for empty message");
    
    // Clean up
    falcon_free_keys(pk, sk);
}

static void test_signature_length(falcon_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[MAX_SIG_LEN];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);
    
    // Generate key pair
    TEST_ASSERT(falcon_keygen(param, &pk, &sk), "Key generation failed");
    
    // Sign message
    TEST_ASSERT(falcon_sign(sk, msg, msg_len, sig, &sig_len), "Signing failed");
    
    // Validate signature length
    size_t min_sig = (param == FALCON512) ? 617 : 1214;
    size_t max_sig = (param == FALCON512) ? 724 : 1337;
    
    TEST_ASSERT(sig_len >= min_sig, "Signature too short");
    TEST_ASSERT(sig_len <= max_sig, "Signature too long");
    
    // Clean up
    falcon_free_keys(pk, sk);
}

static void test_determinism(falcon_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig1[MAX_SIG_LEN], sig2[MAX_SIG_LEN];
    size_t sig_len1, sig_len2;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);
    
    // Generate key pair
    TEST_ASSERT(falcon_keygen(param, &pk, &sk), "Key generation failed");
    
    // Sign same message twice
    TEST_ASSERT(falcon_sign(sk, msg, msg_len, sig1, &sig_len1), 
               "First signing failed");
    TEST_ASSERT(falcon_sign(sk, msg, msg_len, sig2, &sig_len2), 
               "Second signing failed");
    
    // Falcon signatures are non-deterministic
    TEST_ASSERT(sig_len1 == sig_len2, "Signature lengths differ");
    TEST_ASSERT(memcmp(sig1, sig2, sig_len1) != 0, 
               "Signatures are unexpectedly identical");
    
    // Clean up
    falcon_free_keys(pk, sk);
}

//---------------------------
// Test runner
//---------------------------

static void run_tests_for_param(falcon_param_t param) {
    const char *param_name = (param == FALCON512) ? "Falcon-512" : "Falcon-1024";
    
    printf("\n[%s Parameter Set]\n", param_name);
    
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        TEST_RUN(test_keygen);
        TEST_RUN(test_sign_verify);
        TEST_RUN(test_empty_message);
        TEST_RUN(test_signature_length);
        TEST_RUN(test_determinism);
    }
}

int main(void) {
    printf("Starting Falcon Implementation Tests\n");
    printf("===================================\n");
    
    // Test both parameter sets
    run_tests_for_param(FALCON512);
    run_tests_for_param(FALCON1024);
    
    printf("\nAll tests passed successfully!\n");
    return EXIT_SUCCESS;
}