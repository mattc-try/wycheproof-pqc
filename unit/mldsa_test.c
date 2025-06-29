/**
 * @file dilithium_test.c
 * @brief Dilithium (ML-DSA) unit tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Test configuration
#define TEST_ITERATIONS 100
#define TEST_MSG "Test message for Dilithium signatures"

// Dilithium parameters (corresponding to security levels)
typedef enum {
    DILITHIUM2,
    DILITHIUM3,
    DILITHIUM5
} dilithium_param_t;

// Max buffer sizes for Dilithium. These are approximate maximums for Dilithium5.
// You'll need to replace them with actual values if your implementation uses different sizes.
// Typical sizes (from NIST PQC Round 3 - final spec):
// Dilithium2: pk=1312, sk=2528, sig=2420
// Dilithium3: pk=1952, sk=4016, sig=3293
// Dilithium5: pk=2592, sk=4896, sig=4595
#define MAX_PK_LEN     2600 // Max public key length (for Dilithium5)
#define MAX_SK_LEN     5000 // Max secret key length (for Dilithium5)
#define MAX_SIG_LEN    4600 // Max signature length (for Dilithium5)

//-----------------------------------------------------------------------------
// Dilithium Implementation Interface (MOCK/PLACEHOLDER)
// You MUST implement these functions with your actual Dilithium library calls.
// For liboqs, this means using OQS_SIG_new, OQS_SIG_keypair, OQS_SIG_sign, OQS_SIG_verify, OQS_SIG_free.
//-----------------------------------------------------------------------------

/**
 * @brief Generates a Dilithium key pair for a given parameter set.
 * @param param The Dilithium security level (DILITHIUM2, DILITHIUM3, DILITHIUM5).
 * @param pk_buf Pointer to the buffer for the public key.
 * @param pk_len Pointer to store the public key length.
 * @param sk_buf Pointer to the buffer for the secret key.
 * @param sk_len Pointer to store the secret key length.
 * @return 0 on success, -1 on failure.
 */
int dilithium_keygen(dilithium_param_t param, uint8_t *pk_buf, size_t *pk_len,
                     uint8_t *sk_buf, size_t *sk_len) {
    // --- REPLACE THIS WITH YOUR ACTUAL DILITHIUM KEYGEN IMPLEMENTATION ---
    // Example: Using liboqs
    // OQS_SIG *sig = NULL;
    // const char *alg_name;
    // switch (param) {
    //     case DILITHIUM2: alg_name = OQS_SIG_alg_dilithium_2; break;
    //     case DILITHIUM3: alg_name = OQS_SIG_alg_dilithium_3; break;
    //     case DILITHIUM5: alg_name = OQS_SIG_alg_dilithium_5; break;
    //     default: return -1;
    // }
    // sig = OQS_SIG_new(alg_name);
    // if (!sig) return -1;
    //
    // *pk_len = sig->length_public_key;
    // *sk_len = sig->length_secret_key;
    // int ret = OQS_SIG_keypair(sig, pk_buf, sk_buf);
    // OQS_SIG_free(sig);
    // return (ret == OQS_SUCCESS) ? 0 : -1;

    printf("  (MOCK) Performing dilithium_keygen for param %d\n", param); // For debugging mock
    switch (param) {
        case DILITHIUM2:
            *pk_len = 1312;
            *sk_len = 2528;
            break;
        case DILITHIUM3:
            *pk_len = 1952;
            *sk_len = 4016;
            break;
        case DILITHIUM5:
            *pk_len = 2592;
            *sk_len = 4896;
            break;
        default:
            return -1; // Invalid param
    }
    // Simulate writing to buffers (e.g., fill with dummy data)
    memset(pk_buf, 0xA1, *pk_len);
    memset(sk_buf, 0xB2, *sk_len);
    return 0; // Success
}

/**
 * @brief Signs a message using a Dilithium secret key.
 * @param param The Dilithium security level.
 * @param sk The secret key.
 * @param sk_len The secret key length.
 * @param msg The message to sign.
 * @param msg_len The message length.
 * @param sig_buf Pointer to the buffer for the signature.
 * @param sig_len Pointer to store the signature length.
 * @return 0 on success, -1 on failure.
 */
int dilithium_sign(dilithium_param_t param, const uint8_t *sk, size_t sk_len,
                   const uint8_t *msg, size_t msg_len,
                   uint8_t *sig_buf, size_t *sig_len) {
    // --- REPLACE THIS WITH YOUR ACTUAL DILITHIUM SIGN IMPLEMENTATION ---
    // Example: Using liboqs
    // OQS_SIG *sig = NULL;
    // const char *alg_name;
    // switch (param) { // Determine alg_name from param if needed here
    //     case DILITHIUM2: alg_name = OQS_SIG_alg_dilithium_2; break;
    //     case DILITHIUM3: alg_name = OQS_SIG_alg_dilithium_3; break;
    //     case DILITHIUM5: alg_name = OQS_SIG_alg_dilithium_5; break;
    //     default: return -1;
    // }
    // sig = OQS_SIG_new(alg_name);
    // if (!sig) return -1;
    //
    // *sig_len = sig->length_signature; // Set max expected sig len first
    // int ret = OQS_SIG_sign(sig, sig_buf, sig_len, msg, msg_len, sk);
    // OQS_SIG_free(sig);
    // return (ret == OQS_SUCCESS) ? 0 : -1;

    printf("  (MOCK) Performing dilithium_sign\n"); // For debugging mock

    // Simulate sizes based on Dilithium (adjust if your implementation differs)
    switch (param) {
        case DILITHIUM2: *sig_len = 2420; break;
        case DILITHIUM3: *sig_len = 3293; break;
        case DILITHIUM5: *sig_len = 4595; break;
        default: return -1; // Invalid param
    }
    // Simulate writing to buffer
    memset(sig_buf, 0xC3, *sig_len);
    return 0; // Success
}

/**
 * @brief Verifies a Dilithium signature using a public key.
 * @param param The Dilithium security level.
 * @param pk The public key.
 * @param pk_len The public key length.
 * @param msg The message that was signed.
 * @param msg_len The message length.
 * @param sig The signature to verify.
 * @param sig_len The signature length.
 * @return 0 on valid signature, -1 on invalid signature or other failure.
 */
int dilithium_verify(dilithium_param_t param, const uint8_t *pk, size_t pk_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *sig, size_t sig_len) {
    // --- REPLACE THIS WITH YOUR ACTUAL DILITHIUM VERIFY IMPLEMENTATION ---
    // Example: Using liboqs
    // OQS_SIG *sig_inst = NULL;
    // const char *alg_name;
    // switch (param) { // Determine alg_name from param if needed here
    //     case DILITHIUM2: alg_name = OQS_SIG_alg_dilithium_2; break;
    //     case DILITHIUM3: alg_name = OQS_SIG_alg_dilithium_3; break;
    //     case DILITHIUM5: alg_name = OQS_SIG_alg_dilithium_5; break;
    //     default: return -1;
    // }
    // sig_inst = OQS_SIG_new(alg_name);
    // if (!sig_inst) return -1;
    //
    // int ret = OQS_SIG_verify(sig_inst, msg, msg_len, sig, sig_len, pk);
    // OQS_SIG_free(sig_inst);
    // return (ret == OQS_SUCCESS) ? 0 : -1;

    printf("  (MOCK) Performing dilithium_verify\n"); // For debugging mock
    // Simulate successful verification if signature looks "correct" (based on mock sign)
    // and no specific corruption detected.
    // In a real scenario, this involves cryptographic checks.
    if (sig_len > 0 && sig[0] == 0xC3) {
        // If the first byte was flipped in the test (0xC3 ^ 0xFF), then fail.
        if ((sig[0] ^ 0xFF) == 0xC3) { // This means it was originally 0xC3 and now is 0xC3 ^ 0xFF
            return -1; // Simulate failure for corrupted signature
        }
        return 0; // Simulate success
    }
    return -1; // Simulate failure for unexpected signature
}

// Note: Similar to ML-KEM, if your Dilithium implementation uses dynamic
// allocation for keys/signatures internally that need specific freeing,
// you'd add a `dilithium_free_keys` or similar function here.
// For byte array representations, explicit freeing is usually not needed by the test.

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

static void test_dilithium_keygen(dilithium_param_t param) {
    uint8_t pk[MAX_PK_LEN];
    uint8_t sk[MAX_SK_LEN];
    size_t pk_len, sk_len;

    // Generate key pair
    TEST_ASSERT(dilithium_keygen(param, pk, &pk_len, sk, &sk_len) == 0, "Key generation failed");

    // Validate key lengths based on param
    size_t expected_pk_len, expected_sk_len;
    switch (param) {
        case DILITHIUM2:
            expected_pk_len = 1312;
            expected_sk_len = 2528;
            break;
        case DILITHIUM3:
            expected_pk_len = 1952;
            expected_sk_len = 4016;
            break;
        case DILITHIUM5:
            expected_pk_len = 2592;
            expected_sk_len = 4896;
            break;
        default:
            TEST_ASSERT(0, "Invalid Dilithium parameter for keygen length check");
            return;
    }

    TEST_ASSERT(pk_len == expected_pk_len, "Invalid public key length");
    TEST_ASSERT(sk_len == expected_sk_len, "Invalid secret key length");
}

static void test_dilithium_sign_verify(dilithium_param_t param) {
    uint8_t pk[MAX_PK_LEN];
    uint8_t sk[MAX_SK_LEN];
    size_t pk_len, sk_len;

    uint8_t signature[MAX_SIG_LEN];
    size_t sig_len;

    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);

    // Generate key pair
    TEST_ASSERT(dilithium_keygen(param, pk, &pk_len, sk, &sk_len) == 0, "Key generation failed");

    // Sign message
    TEST_ASSERT(dilithium_sign(param, sk, sk_len, msg, msg_len, signature, &sig_len) == 0, "Signing failed");

    // Verify valid signature
    TEST_ASSERT(dilithium_verify(param, pk, pk_len, msg, msg_len, signature, sig_len) == 0,
               "Verification failed for valid signature");

    // Verify with wrong message (should fail)
    uint8_t bad_msg[] = "Tampered message for Dilithium";
    TEST_ASSERT(dilithium_verify(param, pk, pk_len, bad_msg, sizeof(bad_msg) - 1, signature, sig_len) != 0,
               "Verification passed for wrong message");
}

static void test_dilithium_invalid_signature(dilithium_param_t param) {
    uint8_t pk[MAX_PK_LEN];
    uint8_t sk[MAX_SK_LEN];
    size_t pk_len, sk_len;

    uint8_t signature[MAX_SIG_LEN];
    size_t sig_len;

    const uint8_t *msg = (const uint8_t *)TEST_MSG;
    size_t msg_len = strlen(TEST_MSG);

    // Generate key pair
    TEST_ASSERT(dilithium_keygen(param, pk, &pk_len, sk, &sk_len) == 0, "Key generation failed");

    // Sign message to get a valid signature to corrupt
    TEST_ASSERT(dilithium_sign(param, sk, sk_len, msg, msg_len, signature, &sig_len) == 0, "Signing failed");

    // Corrupt signature
    TEST_ASSERT(sig_len > 0, "Signature length must be > 0 to corrupt");
    signature[0] ^= 0xFF; // Flip a bit in the signature

    // Attempt verification with corrupted signature
    int result = dilithium_verify(param, pk, pk_len, msg, msg_len, signature, sig_len);

    // Verification should fail (return non-zero) for an invalid signature
    TEST_ASSERT(result != 0, "Verification should fail for corrupted signature");
}

//---------------------------
// Test runner
//---------------------------

static void run_tests_for_param(dilithium_param_t param) {
    const char *param_name;
    switch (param) {
        case DILITHIUM2:
            param_name = "Dilithium2";
            break;
        case DILITHIUM3:
            param_name = "Dilithium3";
            break;
        case DILITHIUM5:
            param_name = "Dilithium5";
            break;
        default:
            param_name = "UNKNOWN DILITHIUM PARAM";
            break;
    }

    printf("\n[%s Parameter Set]\n", param_name);

    for (int i = 0; i < TEST_ITERATIONS; i++) {
        TEST_RUN(test_dilithium_keygen, param);
        TEST_RUN(test_dilithium_sign_verify, param);
        TEST_RUN(test_dilithium_invalid_signature, param);
    }
}

int main(void) {
    printf("Starting Dilithium Implementation Tests\n");
    printf("=======================================\n");

    // Test all Dilithium parameter sets
    run_tests_for_param(DILITHIUM2);
    run_tests_for_param(DILITHIUM3);
    run_tests_for_param(DILITHIUM5);

    printf("\nAll Dilithium tests completed successfully!\n");
    return EXIT_SUCCESS;
}
