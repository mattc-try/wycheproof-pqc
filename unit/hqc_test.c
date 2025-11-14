/**
 * @file hqc_test.c
 * @brief HQC KEM scheme unit tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../implementations/hqc.h" // Adjust path as needed

#define TEST_ITERATIONS 100
#define TEST_MSG "Test message for HQC shared secrets"

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

#define TEST_RUN(name, param_val) do { \
    printf(" %-30s", #name); \
    fflush(stdout); \
    name(param_val); \
    printf(" [PASS]\n"); \
} while(0)

//---------------------------
// Test cases
//---------------------------

static void test_hqc_keygen(hqc_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    TEST_ASSERT(hqc_keygen(param, &pk, &sk) == HQC_OK, "Key generation failed");
    TEST_ASSERT(pk != NULL, "Public key is NULL");
    TEST_ASSERT(sk != NULL, "Secret key is NULL");
    hqc_free_keys(pk, sk);
}

static void test_hqc_encaps_decaps(hqc_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    TEST_ASSERT(hqc_keygen(param, &pk, &sk) == HQC_OK, "Key generation failed");
    uint8_t ct[HQC_CT_MAX];
    uint8_t ss_enc[HQC_SS_LEN], ss_dec[HQC_SS_LEN];
    size_t ct_len = HQC_CT_MAX;
    // Encapsulate
    TEST_ASSERT(hqc_encaps(pk, ct, &ct_len, ss_enc) == HQC_OK, "Encapsulation failed");
    // Decapsulate - should recover same shared secret
    TEST_ASSERT(hqc_decaps(sk, ct, ct_len, ss_dec) == HQC_OK, "Decapsulation failed");
    TEST_ASSERT(memcmp(ss_enc, ss_dec, HQC_SS_LEN) == 0, "Shared secrets do not match");
    hqc_free_keys(pk, sk);
}

static void test_hqc_decaps_fail(hqc_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    TEST_ASSERT(hqc_keygen(param, &pk, &sk) == HQC_OK, "Key generation failed");
    uint8_t ct[HQC_CT_MAX];
    uint8_t ss_enc[HQC_SS_LEN], ss_dec[HQC_SS_LEN];
    size_t ct_len = HQC_CT_MAX;
    // Encapsulate
    TEST_ASSERT(hqc_encaps(pk, ct, &ct_len, ss_enc) == HQC_OK, "Encapsulation failed");
    // Corrupt ciphertext
    TEST_ASSERT(ct_len > 0, "Ciphertext length is zero");
    ct[0] ^= 0xFF;
    // Decapsulation should fail or at least produce a different secret
    hqc_decaps(sk, ct, ct_len, ss_dec);
    TEST_ASSERT(memcmp(ss_enc, ss_dec, HQC_SS_LEN) != 0, "Decapsulation should not yield correct shared secret for corrupted ciphertext");
    hqc_free_keys(pk, sk);
}

static void test_hqc_empty_ciphertext(hqc_param_t param) {
    uint8_t *pk = NULL, *sk = NULL;
    TEST_ASSERT(hqc_keygen(param, &pk, &sk) == HQC_OK, "Key generation failed");
    uint8_t ss_dec[HQC_SS_LEN];
    // Pass empty ciphertext
    TEST_ASSERT(hqc_decaps(sk, NULL, 0, ss_dec) == HQC_ERROR, "Decapsulation should fail on empty ciphertext");
    hqc_free_keys(pk, sk);
}

//---------------------------
// Test runner
//---------------------------

static void run_hqc_tests_for_param(hqc_param_t param) {
    const char *param_name = (param == HQC256) ? "HQC-256" : "HQC-512";
    printf("\n[%s Parameter Set]\n", param_name);
    for (int i = 0; i < TEST_ITERATIONS; i++) {
        TEST_RUN(test_hqc_keygen, param);
        TEST_RUN(test_hqc_encaps_decaps, param);
        TEST_RUN(test_hqc_decaps_fail, param);
        TEST_RUN(test_hqc_empty_ciphertext, param);
    }
}

int main(void) {
    printf("Starting HQC KEM Implementation Tests\n");
    printf("====================================\n");
    run_hqc_tests_for_param(HQC256);
    run_hqc_tests_for_param(HQC512);
    printf("\nAll HQC tests completed successfully!\n");
    return EXIT_SUCCESS;
}
