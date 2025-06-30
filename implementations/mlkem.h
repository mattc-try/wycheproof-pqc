/**
 * @file mlkem.h
 * @brief Interface for ML-KEM (Module Lattice Key Encapsulation Mechanism)
 */

#ifndef MLKEM_H
#define MLKEM_H

#include <stdint.h>
#include <stddef.h>

// ML-KEM parameter sets
typedef enum {
    MLKEM_512 = 0,   // ML-KEM-512 parameters
    MLKEM_768 = 1,    // ML-KEM-768 parameters
    MLKEM_1024 = 2    // ML-KEM-1024 parameters
} mlkem_param_t;

// Error codes
#define MLKEM_OK                0
#define MLKEM_INVALID_PARAM    -1
#define MLKEM_BUFFER_TOO_SMALL -2
#define MLKEM_DECAP_FAIL       -3
#define MLKEM_RANDOM_FAIL      -4
#define MLKEM_INVALID_CIPHERTEXT -5
#define MLKEM_INTERNAL_ERROR   -6

/**
 * @brief Generates an ML-KEM key pair
 * 
 * @param param ML-KEM parameter set
 * @param pk Output pointer for public key (will be allocated)
 * @param sk Output pointer for private key (will be allocated)
 * @return 0 on success, negative error code on failure
 * 
 * @note Caller must free allocated keys with mlkem_free_keys()
 */
int mlkem_keygen(mlkem_param_t param, uint8_t **pk, uint8_t **sk);

/**
 * @brief Encapsulates a shared secret
 * 
 * @param pk Public key
 * @param ct Output buffer for ciphertext
 * @param ct_len [in] Capacity of ct buffer
 *              [out] Actual ciphertext length
 * @param ss Output buffer for shared secret
 * @param ss_len Length of shared secret (must be 32 bytes)
 * @return 0 on success, negative error code on failure
 */
int mlkem_encaps(const uint8_t *pk, 
                uint8_t *ct, size_t *ct_len,
                uint8_t *ss, size_t ss_len);

/**
 * @brief Decapsulates a shared secret
 * 
 * @param sk Private key
 * @param ct Ciphertext
 * @param ct_len Length of ciphertext in bytes
 * @param ss Output buffer for shared secret
 * @param ss_len Length of shared secret (must be 32 bytes)
 * @return 0 on success, negative error code on failure
 */
int mlkem_decaps(const uint8_t *sk,
                const uint8_t *ct, size_t ct_len,
                uint8_t *ss, size_t ss_len);

/**
 * @brief Frees memory allocated for ML-KEM keys
 * 
 * @param pk Public key to free
 * @param sk Private key to free
 */
void mlkem_free_keys(uint8_t *pk, uint8_t *sk);

// Standardized parameter sizes (in bytes)
#define MLKEM_512_PK_LEN   800
#define MLKEM_512_SK_LEN   1632
#define MLKEM_512_CT_LEN   768
#define MLKEM_512_SS_LEN   32

#define MLKEM_768_PK_LEN   1184
#define MLKEM_768_SK_LEN   2400
#define MLKEM_768_CT_LEN   1088
#define MLKEM_768_SS_LEN   32

#define MLKEM_1024_PK_LEN  1568
#define MLKEM_1024_SK_LEN  3168
#define MLKEM_1024_CT_LEN  1568
#define MLKEM_1024_SS_LEN  32

#endif // MLKEM_H