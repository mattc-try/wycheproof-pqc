/**
 * @file sphincs_test.c
 * @brief SPHINCS+ signature scheme unit tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../implementations/sphincs.h" // Adjust include as necessary

#define TEST_ITERATIONS 100
#define TEST_MSG "Test message for SPHINCS+ signatures"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

#define TEST_RUN(name, param_val) do { \
    printf(" %-35s", #name); \
    fflush(stdout); \
    name(param_val); \
    printf(" [PASS]\n"); \
} while(0)

//---------------------------
// Test cases
//---------------------------

static void test_sphincs_keygen(sphincs_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    TEST_ASSERT(sphincs_keygen(param, &pk, &sk) == SPHINCS_OK, "Key generation failed");
    TEST_ASSERT(pk != NULL, "Public key is NULL");
    TEST_ASSERT(sk != NULL, "Secret key is NULL");
    sphincs_free_keys(pk, sk);
}

static void test_sphincs_sign_verify(sphincs_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[SPHINCS_SIG_MAX]; // Use max defined buffer
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);

    TEST_ASSERT(sphincs_keygen(param, &pk, &sk) == SPHINCS_OK, "Key generation failed");
    sig_len = SPHINCS_SIG_MAX;
    TEST_ASSERT(sphincs_sign(sk, msg, msg_len, sig, &sig_len) == SPHINCS_OK, "Signing failed");
    TEST_ASSERT(sphincs_verify(pk, msg, msg_len, sig, sig_len) == SPHINCS_OK,
        "Verification failed for valid signature");
    sphincs_free_keys(pk, sk);
}

static void test_sphincs_tampered_signature(sphincs_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[SPHINCS_SIG_MAX];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);

    TEST_ASSERT(sphincs_keygen(param, &pk, &sk) == SPHINCS_OK, "Key generation failed");
    sig_len = SPHINCS_SIG_MAX;
    TEST_ASSERT(sphincs_sign(sk, msg, msg_len, sig, &sig_len) == SPHINCS_OK, "Signing failed");
    // Tamper with signature
    TEST_ASSERT(sig_len > 0, "Signature length is zero");
    sig[0] ^= 0xFF;
    TEST_ASSERT(sphincs_verify(pk, msg, msg_len, sig, sig_len) == SPHINCS_VERIFY_FAIL,
        "Verification should fail for tampered signature");
    sphincs_free_keys(pk, sk);
}

static void test_sphincs_wrong_message(sphincs_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[SPHINCS_SIG_MAX];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    const uint8_t *bad_msg = (const uint8_t *)"Tampered message";
    size_t msg_len = strlen(TEST_MSG);
    size_t bad_msg_len = strlen("Tampered message");

    TEST_ASSERT(sphincs_keygen(param, &pk, &sk) == SPHINCS_OK, "Key generation failed");
    sig_len = SPHINCS_SIG_MAX;
    TEST_ASSERT(sphincs_sign(sk, msg, msg_len, sig, &sig_len) == SPHINCS_OK, "Signing failed");
    TEST_ASSERT(sphincs_verify(pk, bad_msg, bad_msg_len, sig, sig_len) == SPHINCS_VERIFY_FAIL,
        "Verification should fail for wrong message");
    sphincs_free_keys(pk, sk);
}

static void test_sphincs_empty_message(sphincs_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[SPHINCS_SIG_MAX];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)"";
    size_t msg_len = 0;

    TEST_ASSERT(sphincs_keygen(param, &pk, &sk) == SPHINCS_OK, "Key generation failed");
    sig_len = SPHINCS_SIG_MAX;
    TEST_ASSERT(sphincs_sign(sk, msg, msg_len, sig, &sig_len) == SPHINCS_OK,
        "Signing empty message failed");
    TEST_ASSERT(sphincs_verify(pk, msg, msg_len, sig, sig_len) == SPHINCS_OK,
        "Verification failed for empty message");
    sphincs_free_keys(pk, sk);
}

static void test_sphincs_signature_length(sphincs_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    uint8_t sig[SPHINCS_SIG_MAX];
    size_t sig_len;
    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);

    TEST_ASSERT(sphincs_keygen(param, &pk, &sk) == SPHINCS_OK, "Key generation failed");
    sig_len = SPHINCS_SIG_MAX;
    TEST_ASSERT(sphincs_sign(sk, msg, msg_len, sig, &sig_len) == SPHINCS_OK, "Signing failed");
    // Expect signature length to be fixed per parameter set
    size_t expected_sig_len = sphincs_expected_siglen(param);
    TEST_ASSERT(sig_len == expected_sig_len, "Signature length mismatch");
    sphincs_free_keys(pk, sk);
}

//---------------------------
// Test runner
//---------------------------

static void run_sphincs_tests_for_param(sphincs_param_t param) {
    const char *param_name;
    switch (param) {
        case SPHINCS_SHA2_128F:  param_name = "SPHINCS+-SHA2-128f";  break;
        case SPHINCS_SHA2_192S:  param_name = "SPHINCS+-SHA2-192s";  break;
        // Add additional parameter set names as needed
        default: param_name = "UNKNOWN SPHINCS+ PARAM"; break;
    }
    printf("\n[%s Parameter Set]\n", param_name);
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        TEST_RUN(test_sphincs_keygen, param);
        TEST_RUN(test_sphincs_sign_verify, param);
        TEST_RUN(test_sphincs_tampered_signature, param);
        TEST_RUN(test_sphincs_wrong_message, param);
        TEST_RUN(test_sphincs_empty_message, param);
        TEST_RUN(test_sphincs_signature_length, param);
    }
}

int main(void) {
    printf("Starting SPHINCS+ Implementation Tests\n");
    printf("======================================\n");
    run_sphincs_tests_for_param(SPHINCS_SHA2_128F);
    run_sphincs_tests_for_param(SPHINCS_SHA2_192S);
    printf("\nAll SPHINCS+ tests completed successfully!\n");
    return EXIT_SUCCESS;
}
