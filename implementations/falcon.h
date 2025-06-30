/**
 * @file falcon.h
 * @brief Interface for Falcon digital signature scheme
 */

#ifndef FALCON_H
#define FALCON_H

#include <stdint.h>
#include <stddef.h>

// Falcon parameter sets
typedef enum {
    FALCON512 = 0,   // Falcon-512 parameters
    FALCON1024 = 1    // Falcon-1024 parameters
} falcon_param_t;

// Error codes
#define FALCON_OK              0
#define FALCON_INVALID_PARAM  -1
#define FALCON_BUFFER_TOO_SMALL -2
#define FALCON_VERIFY_FAIL    -3
#define FALCON_INVALID_SIGNATURE -4
#define FALCON_INTERNAL_ERROR -5

/**
 * @brief Generates a Falcon key pair
 * 
 * @param param Falcon parameter set (FALCON512 or FALCON1024)
 * @param pk Output pointer for public key (will be allocated)
 * @param sk Output pointer for private key (will be allocated)
 * @return 0 on success, negative error code on failure
 * 
 * @note The caller is responsible for freeing allocated keys with falcon_free_keys()
 */
int falcon_keygen(falcon_param_t param, uint8_t **pk, uint8_t **sk);

/**
 * @brief Signs a message using Falcon
 * 
 * @param sk Private key
 * @param msg Message to sign
 * @param msg_len Length of message in bytes
 * @param sig Output buffer for signature
 * @param sig_len [in] Capacity of sig buffer
 *              [out] Actual signature length
 * @return 0 on success, negative error code on failure
 */
int falcon_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len);

/**
 * @brief Verifies a Falcon signature
 * 
 * @param pk Public key
 * @param msg Signed message
 * @param msg_len Length of message in bytes
 * @param sig Signature to verify
 * @param sig_len Length of signature in bytes
 * @return 0 if signature is valid, negative error code if invalid
 */
int falcon_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

/**
 * @brief Frees memory allocated for Falcon keys
 * 
 * @param pk Public key to free
 * @param sk Private key to free
 */
void falcon_free_keys(uint8_t *pk, uint8_t *sk);

// Helper macros for buffer sizes
#define FALCON512_PK_LEN 897
#define FALCON512_SK_LEN 1281
#define FALCON512_SIG_MAX 690

#define FALCON1024_PK_LEN 1793
#define FALCON1024_SK_LEN 2305
#define FALCON1024_SIG_MAX 1330

#endif // FALCON_H