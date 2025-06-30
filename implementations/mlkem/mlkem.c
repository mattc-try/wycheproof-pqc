/**
 * @file mlkem.c
 * @brief Stub implementations for ML-KEM (Module Lattice Key Encapsulation Mechanism) functions.
 * These are empty functions to allow compilation and linking.
 * They do not perform any actual cryptographic operations.
 */

#include "../mlkem.h"
#include <stdlib.h> // For NULL, malloc, free
#include <stdio.h>  // For fprintf (for debugging/placeholder messages)
#include <string.h> // For memset

/**
 * @brief Stub implementation for mlkem_keygen.
 * Generates dummy public and private keys (allocated memory filled with zeros).
 */
int mlkem_keygen(mlkem_param_t param, uint8_t **pk, uint8_t **sk) {
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "mlkem_keygen (stub): Public or secret key output pointer is NULL.\n");
        return MLKEM_INTERNAL_ERROR;
    }

    size_t pk_len = 0;
    size_t sk_len = 0;

    switch (param) {
        case MLKEM_512:
            pk_len = MLKEM_512_PK_LEN;
            sk_len = MLKEM_512_SK_LEN;
            break;
        case MLKEM_768:
            pk_len = MLKEM_768_PK_LEN;
            sk_len = MLKEM_768_SK_LEN;
            break;
        case MLKEM_1024:
            pk_len = MLKEM_1024_PK_LEN;
            sk_len = MLKEM_1024_SK_LEN;
            break;
        default:
            fprintf(stderr, "mlkem_keygen (stub): Invalid ML-KEM parameter set: %d.\n", param);
            return MLKEM_INVALID_PARAM;
    }

    // Allocate dummy public key memory
    *pk = (uint8_t*)malloc(pk_len);
    if (*pk == NULL) {
        fprintf(stderr, "mlkem_keygen (stub): Failed to allocate dummy public key memory.\n");
        return MLKEM_INTERNAL_ERROR;
    }
    memset(*pk, 0x00, pk_len); // Initialize with zeros

    // Allocate dummy secret key memory
    *sk = (uint8_t*)malloc(sk_len);
    if (*sk == NULL) {
        fprintf(stderr, "mlkem_keygen (stub): Failed to allocate dummy secret key memory.\n");
        free(*pk); // Clean up public key if secret key allocation fails
        *pk = NULL;
        return MLKEM_INTERNAL_ERROR;
    }
    memset(*sk, 0x00, sk_len); // Initialize with zeros
    
    fprintf(stderr, "mlkem_keygen (stub): Dummy key pair generated for param %d.\n", param);
    return MLKEM_OK;
}

/**
 * @brief Stub implementation for mlkem_encaps.
 * Fills ciphertext and shared secret buffers with dummy data.
 */
int mlkem_encaps(const uint8_t *pk, 
                uint8_t *ct, size_t *ct_len,
                uint8_t *ss, size_t ss_len) {
    if (pk == NULL || ct == NULL || ct_len == NULL || ss == NULL) {
        fprintf(stderr, "mlkem_encaps (stub): Invalid input pointers.\n");
        return MLKEM_INTERNAL_ERROR;
    }

    if (ss_len != MLKEM_512_SS_LEN) { // Shared secret length is fixed at 32 bytes for all ML-KEM
        fprintf(stderr, "mlkem_encaps (stub): Invalid shared secret length: %zu (expected %d).\n", ss_len, MLKEM_512_SS_LEN);
        return MLKEM_INVALID_PARAM;
    }

    // Determine a dummy ciphertext length based on common sizes, or a fixed value
    // For simplicity, let's use a fixed dummy length that should fit most buffers
    size_t required_ct_len = MLKEM_512_CT_LEN; // Use the smallest CT length as a default dummy

    if (*ct_len < required_ct_len) {
        fprintf(stderr, "mlkem_encaps (stub): Ciphertext buffer too small (capacity %zu, needed %zu).\n", *ct_len, required_ct_len);
        return MLKEM_BUFFER_TOO_SMALL;
    }

    // Fill ciphertext with dummy data
    memset(ct, 0xBB, required_ct_len);
    *ct_len = required_ct_len;

    // Fill shared secret with dummy data
    memset(ss, 0xCC, ss_len);

    fprintf(stderr, "mlkem_encaps (stub): Dummy ciphertext and shared secret generated. CT Length: %zu\n", *ct_len);
    return MLKEM_OK;
}

/**
 * @brief Stub implementation for mlkem_decaps.
 * Fills shared secret buffer with dummy data and always returns success.
 */
int mlkem_decaps(const uint8_t *sk,
                const uint8_t *ct, size_t ct_len,
                uint8_t *ss, size_t ss_len) {
    if (sk == NULL || ct == NULL || ss == NULL) {
        fprintf(stderr, "mlkem_decaps (stub): Invalid input pointers.\n");
        return MLKEM_INTERNAL_ERROR;
    }

    if (ss_len != MLKEM_512_SS_LEN) { // Shared secret length is fixed at 32 bytes for all ML-KEM
        fprintf(stderr, "mlkem_decaps (stub): Invalid shared secret length: %zu (expected %d).\n", ss_len, MLKEM_512_SS_LEN);
        return MLKEM_INVALID_PARAM;
    }

    // Fill shared secret with dummy data (e.g., to simulate successful decapsulation)
    memset(ss, 0xDD, ss_len);

    fprintf(stderr, "mlkem_decaps (stub): Dummy shared secret decapsulated. CT Length: %zu\n", ct_len);
    // You can choose to return MLKEM_DECAP_FAIL or MLKEM_OK based on test needs.
    // For initial linking, returning OK is fine.
    return MLKEM_OK; 
}

/**
 * @brief Stub implementation for mlkem_free_keys.
 * Frees dummy allocated memory for public and private keys.
 */
void mlkem_free_keys(uint8_t *pk, uint8_t *sk) {
    if (pk != NULL) {
        free(pk);
        fprintf(stderr, "mlkem_free_keys (stub): Public key freed.\n");
    }
    if (sk != NULL) {
        free(sk);
        fprintf(stderr, "mlkem_free_keys (stub): Secret key freed.\n");
    }
}
