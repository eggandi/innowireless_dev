/** 
  * @file 
  * @brief 
  * @date 2022-04-28 
  * @author gyun 
  */


#ifndef V2X_SW_DOT2_ENCRYPT_H
#define V2X_SW_DOT2_ENCRYPT_H


// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"

#ifdef __cplusplus
extern "C" {
#endif

// dot2-ecies.c
int INTERNAL dot2_ECDH(const struct Dot2ECPrivateKey *privkey_a, const struct Dot2ECPublicKey *pubkey_B, uint8_t *ss_x);
uint8_t INTERNAL * dot2_KDF2_SHA256(const uint8_t *ss_x, size_t ss_x_len, const uint8_t *kdp, size_t kdp_len, size_t desired_len);
int INTERNAL dot2_HMAC_SHA256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, struct Dot2AESAuthTag *auth_tag);
int INTERNAL dot2_ECIES_Encrypt(const struct Dot2ECPrivateKey *v, const struct Dot2AESKey *k, const struct Dot2SHA256 *p1, const struct Dot2ECPublicKey *R, struct Dot2AESKey *C, struct Dot2AESAuthTag *T);
int INTERNAL dot2_ECIES_Decrypt(const struct Dot2ECPublicKey *V, const struct Dot2AESKey *C, const struct Dot2AESAuthTag *T, const struct Dot2ECPrivateKey *r, const struct Dot2SHA256 *p1, struct Dot2AESKey *k);

// dot2-encrypt.c
uint8_t INTERNAL * dot2_AES_CCM_128_Encrypt(const uint8_t *plaintext, size_t plaintext_len, const struct Dot2AESKey *key, const struct Dot2AESNonce *nonce, int *ret);
uint8_t INTERNAL * dot2_EncryptDataAndKey(const uint8_t *data, size_t data_len, const struct Dot2AESKey *k, const struct Dot2AESNonce *n, const struct Dot2ECPrivateKey *v, const struct Dot2SHA256 *p1, const struct Dot2ECPublicKey *R, struct Dot2AESKey *C, struct Dot2AESAuthTag *T, int *ret);
uint8_t INTERNAL * dot2_EncryptData_1(const uint8_t *data, size_t data_len, const uint8_t *key_input, size_t key_input_size, struct Dot2ECPublicKey *pubkey_r, struct Dot2ECPublicKey *V, struct Dot2AESKey *C, struct Dot2AESAuthTag *T, struct Dot2AESNonce *nonce, int *ret);
uint8_t INTERNAL * dot2_EncryptData_2(const uint8_t *data, size_t data_len, const struct Dot2SHA256 *key_input_h, struct Dot2ECPublicKey *pubkey_r, struct Dot2ECPublicKey *V, struct Dot2AESKey *C, struct Dot2AESAuthTag *T, struct Dot2AESNonce *nonce, int *ret);
uint8_t INTERNAL * dot2_AES_CCM_128_Decrypt(uint8_t *ciphertext_and_tag, size_t ciphertext_and_tag_len, const struct Dot2AESKey *key, const struct Dot2AESNonce *nonce, int *ret);
uint8_t INTERNAL * dot2_DecryptDataAndKey(uint8_t *ciphertext_and_tag, size_t ciphertext_and_tag_len, const struct Dot2AESNonce *n, const struct Dot2AESKey *C, const struct Dot2ECPublicKey *V, const struct Dot2AESAuthTag *T, const struct Dot2ECPrivateKey *r, const struct Dot2SHA256 *p1, int *ret);
uint8_t INTERNAL * dot2_DecryptData_1(uint8_t *data, size_t data_len, const uint8_t *key_input, size_t key_input_size, const struct Dot2ECPrivateKey *privkey, const struct Dot2ECPublicKey *V, const struct Dot2AESKey *C, const struct Dot2AESAuthTag *T, const struct Dot2AESNonce *nonce, int *ret);
uint8_t INTERNAL * dot2_DecryptData_2(uint8_t *data, size_t data_len, const struct Dot2SHA256 *key_input_h, const struct Dot2ECPrivateKey *privkey, const struct Dot2ECPublicKey *V, const struct Dot2AESKey *C, const struct Dot2AESAuthTag *T, const struct Dot2AESNonce *nonce, int *ret);


#ifdef __cplusplus
}
#endif

#endif //V2X_SW_DOT2_ENCRYPT_H
