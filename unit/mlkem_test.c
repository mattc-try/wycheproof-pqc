/**
 * @file mlkem_test.c
 * @brief ML-KEM (Kyber) unit tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Test configuration
#define TEST_ITERATIONS 100 // Reduced for faster testing, adjust as needed

// ML-KEM parameters (corresponding to Kyber security levels)
typedef enum {
    MLKEM512,
    MLKEM768,
    MLKEM1024
} mlkem_param_t;

// Max buffer sizes for ML-KEM. These are placeholder values.
// You'll need to replace them with actual ML-KEM KEM sizes for your implementation.
// For Kyber, typical sizes are:
// Kyber512: pk=800, sk=1632, ct=768, ss=32
// Kyber768: pk=1184, sk=2400, ct=1088, ss=32
// Kyber1024: pk=1568, sk=3168, ct=1568, ss=32
#define MAX_PK_LEN     3200 // Max public key length (for MLKEM1024)
#define MAX_SK_LEN     3200 // Max secret key length (for MLKEM1024)
#define MAX_CT_LEN     1600 // Max ciphertext length (for MLKEM1024)
#define MAX_SS_LEN     32   // Fixed shared secret length

//-----------------------------------------------------------------------------
// ML-KEM Implementation Interface (MOCK/PLACEHOLDER)
// You MUST implement these functions with your actual ML-KEM library calls.
// These are the equivalents of your falcon_* functions.
//-----------------------------------------------------------------------------

/**
 * @brief Generates an ML-KEM key pair.
 * @param param The ML-KEM security level (MLKEM512, MLKEM768, MLKEM1024).
 * @param pk_buf Pointer to the buffer for the public key.
 * @param pk_len Pointer to store the public key length.
 * @param sk_buf Pointer to the buffer for the secret key.
 * @param sk_len Pointer to store the secret key length.
 * @return 0 on success, -1 on failure.
 */
int mlkem_keygen(mlkem_param_t param, uint8_t *pk_buf, size_t *pk_len,
                 uint8_t *sk_buf, size_t *sk_len) {
    // --- REPLACE THIS WITH YOUR ACTUAL ML-KEM KEYGEN IMPLEMENTATION ---
    // Example: based on Kyber 512/768/1024 sizes
    printf("  (MOCK) Performing mlkem_keygen for param %d\n", param); // For debugging mock
    switch (param) {
        case MLKEM512:
            *pk_len = 800;
            *sk_len = 1632;
            break;
        case MLKEM768:
            *pk_len = 1184;
            *sk_len = 2400;
            break;
        case MLKEM1024:
            *pk_len = 1568;
            *sk_len = 3168;
            break;
        default:
            return -1; // Invalid param
    }
    // Simulate writing to buffers (e.g., fill with dummy data)
    memset(pk_buf, 0xAA, *pk_len);
    memset(sk_buf, 0xBB, *sk_len);
    return 0; // Success
}

/**
 * @brief Encapsulates a shared secret using a public key.
 * @param pk The public key.
 * @param pk_len The public key length.
 * @param ct_buf Pointer to the buffer for the ciphertext.
 * @param ct_len Pointer to store the ciphertext length.
 * @param ss_buf Pointer to the buffer for the shared secret.
 * @param ss_len Pointer to store the shared secret length.
 * @return 0 on success, -1 on failure.
 */
int mlkem_encapsulate(const uint8_t *pk, size_t pk_len,
                       uint8_t *ct_buf, size_t *ct_len,
                       uint8_t *ss_buf, size_t *ss_len) {
    // --- REPLACE THIS WITH YOUR ACTUAL ML-KEM ENCAPSULATE IMPLEMENTATION ---
    printf("  (MOCK) Performing mlkem_encapsulate\n"); // For debugging mock

    // Simulate sizes based on Kyber (adjust if your implementation differs)
    if (pk_len == 800) *ct_len = 768; // MLKEM512
    else if (pk_len == 1184) *ct_len = 1088; // MLKEM768
    else if (pk_len == 1568) *ct_len = 1568; // MLKEM1024
    else return -1; // Invalid public key length

    *ss_len = MAX_SS_LEN; // Shared secret length is typically fixed

    // Simulate writing to buffers
    memset(ct_buf, 0xCC, *ct_len);
    memset(ss_buf, 0xDD, *ss_len);
    return 0; // Success
}

/**
 * @brief Decapsulates a shared secret using a secret key and ciphertext.
 * @param sk The secret key.
 * @param sk_len The secret key length.
 * @param ct The ciphertext.
 * @param ct_len The ciphertext length.
 * @param ss_buf Pointer to the buffer for the decapsulated shared secret.
 * @param ss_len Pointer to store the decapsulated shared secret length.
 * @return 0 on success, -1 on failure (e.g., invalid ciphertext).
 */
int mlkem_decapsulate(const uint8_t *sk, size_t sk_len,
                       const uint8_t *ct, size_t ct_len,
                       uint8_t *ss_buf, size_t *ss_len) {
    // --- REPLACE THIS WITH YOUR ACTUAL ML-KEM DECAPSULATE IMPLEMENTATION ---
    printf("  (MOCK) Performing mlkem_decapsulate\n"); // For debugging mock

    *ss_len = MAX_SS_LEN; // Shared secret length is typically fixed

    // Simulate successful decapsulation: copy a known "correct" secret
    // In a real implementation, this would involve complex math.
    // For this mock, we'll just fill it with dummy data.
    memset(ss_buf, 0xDD, *ss_len); // Matches what encaps produced

    // Simulate a failure if ciphertext is clearly wrong (e.g., first byte flipped)
    // This is a simplistic check; real decapsulation has robust failure mechanisms.
    if (ct_len > 0 && ct[0] == 0xCC ^ 0xFF) { // Check against the flipped byte
        return -1; // Simulate decapsulation failure due to bad ciphertext
    }
    return 0; // Success
}

// Note: ML-KEM usually doesn't have explicit "free" functions for keys
// if they are just byte arrays. If your implementation requires dynamic
// allocation within the library and has specific free functions,
// declare and implement them here.
// For this general case, we assume keys are handled as byte arrays by the caller.

//---------------------------
// Test utilities
//---------------------------

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
    uint8_t pk[MAX_PK_LEN];
    uint8_t sk[MAX_SK_LEN];
    size_t pk_len, sk_len;

    // Generate key pair
    TEST_ASSERT(mlkem_keygen(param, pk, &pk_len, sk, &sk_len) == 0, "Key generation failed");

    // Validate key lengths based on param
    size_t expected_pk_len, expected_sk_len;
    switch (param) {
        case MLKEM512:
            expected_pk_len = 800;
            expected_sk_len = 1632;
            break;
        case MLKEM768:
            expected_pk_len = 1184;
            expected_sk_len = 2400;
            break;
        case MLKEM1024:
            expected_pk_len = 1568;
            expected_sk_len = 3168;
            break;
        default:
            TEST_ASSERT(0, "Invalid ML-KEM parameter for keygen length check");
            return;
    }

    TEST_ASSERT(pk_len == expected_pk_len, "Invalid public key length");
    TEST_ASSERT(sk_len == expected_sk_len, "Invalid secret key length");

    // No explicit free for stack/static buffers here, as per ML-KEM typical usage.
    // If your `mlkem_keygen` dynamically allocates, you'll need a `mlkem_free_keys`
    // and call it here.
}

static void test_mlkem_encaps_decaps(mlkem_param_t param) {
    uint8_t pk[MAX_PK_LEN];
    uint8_t sk[MAX_SK_LEN];
    size_t pk_len, sk_len;

    uint8_t ciphertext[MAX_CT_LEN];
    uint8_t shared_secret_encaps[MAX_SS_LEN];
    uint8_t shared_secret_decaps[MAX_SS_LEN];
    size_t ct_len, ss_encaps_len, ss_decaps_len;

    // Generate key pair
    TEST_ASSERT(mlkem_keygen(param, pk, &pk_len, sk, &sk_len) == 0, "Key generation failed");

    // Encapsulation
    TEST_ASSERT(mlkem_encapsulate(pk, pk_len, ciphertext, &ct_len,
                                  shared_secret_encaps, &ss_encaps_len) == 0, "Encapsulation failed");

    // Decapsulation
    TEST_ASSERT(mlkem_decapsulate(sk, sk_len, ciphertext, ct_len,
                                  shared_secret_decaps, &ss_decaps_len) == 0, "Decapsulation failed");

    // Verify shared secrets match
    TEST_ASSERT(ss_encaps_len == MAX_SS_LEN, "Encapsulated shared secret length incorrect");
    TEST_ASSERT(ss_decaps_len == MAX_SS_LEN, "Decapsulated shared secret length incorrect");
    TEST_ASSERT(memcmp(shared_secret_encaps, shared_secret_decaps, MAX_SS_LEN) == 0,
               "Encapsulated and decapsulated secrets do not match");
}

static void test_mlkem_invalid_ciphertext(mlkem_param_t param) {
    uint8_t pk[MAX_PK_LEN];
    uint8_t sk[MAX_SK_LEN];
    size_t pk_len, sk_len;

    uint8_t ciphertext[MAX_CT_LEN];
    uint8_t shared_secret_encaps[MAX_SS_LEN];
    uint8_t shared_secret_decaps[MAX_SS_LEN];
    size_t ct_len, ss_encaps_len, ss_decaps_len;

    // Generate key pair
    TEST_ASSERT(mlkem_keygen(param, pk, &pk_len, sk, &sk_len) == 0, "Key generation failed");

    // Encapsulation to get a valid ciphertext to corrupt
    TEST_ASSERT(mlkem_encapsulate(pk, pk_len, ciphertext, &ct_len,
                                  shared_secret_encaps, &ss_encaps_len) == 0, "Encapsulation failed");

    // Corrupt the ciphertext
    TEST_ASSERT(ct_len > 0, "Ciphertext length must be > 0 to corrupt");
    ciphertext[0] ^= 0xFF; // Flip a bit in the ciphertext

    // Attempt decapsulation with corrupted ciphertext
    // A proper ML-KEM implementation should return a non-zero value on failure,
    // or produce a different shared secret than the original.
    int result = mlkem_decapsulate(sk, sk_len, ciphertext, ct_len,
                                   shared_secret_decaps, &ss_decaps_len);

    // This test assumes that a failure in decapsulation for invalid ciphertext
    // will either return a non-zero result or produce a different shared secret.
    if (result == 0) { // If decapsulation "succeeded" (returned 0)
        TEST_ASSERT(memcmp(shared_secret_encaps, shared_secret_decaps, MAX_SS_LEN) != 0,
                   "Decapsulation with invalid ciphertext should not produce the same secret");
    } else {
        // If it returned non-zero (failed), that's also a valid outcome for invalid ciphertext.
        printf("  (Decapsulation with invalid ciphertext returned non-zero, as expected)\n");
    }
}

//---------------------------
// Test runner
//---------------------------

static void run_tests_for_param(mlkem_param_t param) {
    const char *param_name;
    switch (param) {
        case MLKEM512:
            param_name = "ML-KEM-512";
            break;
        case MLKEM768:
            param_name = "ML-KEM-768";
            break;
        case MLKEM1024:
            param_name = "ML-KEM-1024";
            break;
        default:
            param_name = "UNKNOWN ML-KEM PARAM";
            break;
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
    printf("====================================\n");

    // Test all ML-KEM parameter sets
    run_tests_for_param(MLKEM512);
    run_tests_for_param(MLKEM768);
    run_tests_for_param(MLKEM1024);

    printf("\nAll ML-KEM tests completed successfully!\n");
    return EXIT_SUCCESS;
}