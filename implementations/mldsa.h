/**
 * @file mldsa.h
 * @brief Interface for ML-DSA (Module Lattice Digital Signature Algorithm)
 */

#ifndef MLDSA_H
#define MLDSA_H

#include <stdint.h>
#include <stddef.h>

// ML-DSA parameter sets
typedef enum {
    MLDSA_44 = 0,   // ML-DSA-44 parameters
    MLDSA_65 = 1,    // ML-DSA-65 parameters
    MLDSA_87 = 2     // ML-DSA-87 parameters
} mldsa_param_t;

// Error codes
#define MLDSA_OK                0
#define MLDSA_INVALID_PARAM    -1
#define MLDSA_BUFFER_TOO_SMALL -2
#define MLDSA_VERIFY_FAIL      -3
#define MLDSA_INVALID_SIG      -4
#define MLDSA_RANDOM_FAIL      -5
#define MLDSA_INTERNAL_ERROR   -6

/**
 * @brief Generates an ML-DSA key pair
 * 
 * @param param ML-DSA parameter set
 * @param pk Output pointer for public key (will be allocated)
 * @param sk Output pointer for private key (will be allocated)
 * @return 0 on success, negative error code on failure
 * 
 * @note Caller must free allocated keys with mldsa_free_keys()
 */
int mldsa_keygen(mldsa_param_t param, uint8_t **pk, uint8_t **sk);

/**
 * @brief Signs a message using ML-DSA
 * 
 * @param sk Private key
 * @param msg Message to sign
 * @param msg_len Length of message in bytes
 * @param sig Output buffer for signature
 * @param sig_len [in] Capacity of sig buffer
 *                [out] Actual signature length
 * @return 0 on success, negative error code on failure
 */
int mldsa_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
               uint8_t *sig, size_t *sig_len);

/**
 * @brief Verifies an ML-DSA signature
 * 
 * @param pk Public key
 * @param msg Signed message
 * @param msg_len Length of message in bytes
 * @param sig Signature to verify
 * @param sig_len Length of signature in bytes
 * @return 0 if signature is valid, negative error code if invalid
 */
int mldsa_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len);

/**
 * @brief Frees memory allocated for ML-DSA keys
 * 
 * @param pk Public key to free
 * @param sk Private key to free
 */
void mldsa_free_keys(uint8_t *pk, uint8_t *sk);

// Standardized parameter sizes (in bytes)
#define MLDSA_44_PK_LEN   1184
#define MLDSA_44_SK_LEN   2800
#define MLDSA_44_SIG_MAX  2044

#define MLDSA_65_PK_LEN   1760
#define MLDSA_65_SK_LEN   3856
#define MLDSA_65_SIG_MAX  2701

#define MLDSA_87_PK_LEN   2592
#define MLDSA_87_SK_LEN   4864
#define MLDSA_87_SIG_MAX  3366

#endif // MLDSA_H