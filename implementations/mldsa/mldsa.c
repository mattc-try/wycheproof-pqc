/**
 * @file mldsa.c
 * @brief Stub implementations for ML-DSA (Module Lattice Digital Signature Algorithm) functions.
 * These are empty functions to allow compilation and linking.
 * They do not perform any actual cryptographic operations.
 */

#include "../mldsa.h"
#include <stdlib.h> // For NULL, malloc, free
#include <stdio.h>  // For fprintf (for debugging/placeholder messages)
#include <string.h> // For memset

/**
 * @brief Stub implementation for mldsa_keygen.
 * Generates dummy public and private keys (allocated memory filled with zeros).
 */
int mldsa_keygen(mldsa_param_t param, uint8_t **pk, uint8_t **sk) {
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "mldsa_keygen (stub): Public or secret key output pointer is NULL.\n");
        return MLDSA_INTERNAL_ERROR;
    }

    size_t pk_len = 0;
    size_t sk_len = 0;

    switch (param) {
        case MLDSA_44:
            pk_len = MLDSA_44_PK_LEN;
            sk_len = MLDSA_44_SK_LEN;
            break;
        case MLDSA_65:
            pk_len = MLDSA_65_PK_LEN;
            sk_len = MLDSA_65_SK_LEN;
            break;
        case MLDSA_87:
            pk_len = MLDSA_87_PK_LEN;
            sk_len = MLDSA_87_SK_LEN;
            break;
        default:
            fprintf(stderr, "mldsa_keygen (stub): Invalid ML-DSA parameter set: %d.\n", param);
            return MLDSA_INVALID_PARAM;
    }

    // Allocate dummy public key memory
    *pk = (uint8_t*)malloc(pk_len);
    if (*pk == NULL) {
        fprintf(stderr, "mldsa_keygen (stub): Failed to allocate dummy public key memory.\n");
        return MLDSA_INTERNAL_ERROR;
    }
    memset(*pk, 0x00, pk_len); // Initialize with zeros

    // Allocate dummy secret key memory
    *sk = (uint8_t*)malloc(sk_len);
    if (*sk == NULL) {
        fprintf(stderr, "mldsa_keygen (stub): Failed to allocate dummy secret key memory.\n");
        free(*pk); // Clean up public key if secret key allocation fails
        *pk = NULL;
        return MLDSA_INTERNAL_ERROR;
    }
    memset(*sk, 0x00, sk_len); // Initialize with zeros
    
    fprintf(stderr, "mldsa_keygen (stub): Dummy key pair generated for param %d.\n", param);
    return MLDSA_OK;
}

/**
 * @brief Stub implementation for mldsa_sign.
 * Fills signature buffer with dummy data.
 */
int mldsa_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
               uint8_t *sig, size_t *sig_len) {
    if (sk == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
        fprintf(stderr, "mldsa_sign (stub): Invalid input pointers.\n");
        return MLDSA_INTERNAL_ERROR;
    }

    // Determine a dummy signature length based on common sizes, or a fixed value
    // For simplicity, let's use a fixed dummy length that should fit most buffers
    size_t required_sig_len = MLDSA_44_SIG_MAX / 2; // Arbitrary dummy length

    if (*sig_len < required_sig_len) {
        fprintf(stderr, "mldsa_sign (stub): Signature buffer too small (capacity %zu, needed %zu).\n", *sig_len, required_sig_len);
        return MLDSA_BUFFER_TOO_SMALL;
    }

    // Fill signature with dummy data
    memset(sig, 0xEE, required_sig_len);
    *sig_len = required_sig_len;

    fprintf(stderr, "mldsa_sign (stub): Dummy signature created. Length: %zu\n", *sig_len);
    return MLDSA_OK;
}

/**
 * @brief Stub implementation for mldsa_verify.
 * Always returns MLDSA_VERIFY_FAIL.
 */
int mldsa_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len) {
    if (pk == NULL || msg == NULL || sig == NULL) {
        fprintf(stderr, "mldsa_verify (stub): Invalid input pointers.\n");
        return MLDSA_INTERNAL_ERROR;
    }

    fprintf(stderr, "mldsa_verify (stub): Always returning VERIFY_FAIL.\n");
    return MLDSA_VERIFY_FAIL; // Simulate verification failure
}

/**
 * @brief Stub implementation for mldsa_free_keys.
 * Frees dummy allocated memory for public and private keys.
 */
void mldsa_free_keys(uint8_t *pk, uint8_t *sk) {
    if (pk != NULL) {
        free(pk);
        fprintf(stderr, "mldsa_free_keys (stub): Public key freed.\n");
    }
    if (sk != NULL) {
        free(sk);
        fprintf(stderr, "mldsa_free_keys (stub): Secret key freed.\n");
    }
}
