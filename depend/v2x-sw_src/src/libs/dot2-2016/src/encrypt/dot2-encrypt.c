/** 
  * @file 
  * @brief 
  * @date 2022-04-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "encrypt/dot2-encrypt.h"



/**
 * @brief AES-CCM-128 암호화를 수행한다.
 * @param[in] plaintext 암호화할 평문 (Null 전달 시 EVP_EncryptUpdate()에서 암호화에 실패한다)
 * @param[in] plaintext_len plaintext의 길이
 * @param[in] key AES 암호화 키
 * @param[in] nonce AES Nonce N
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 암호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 암호화된 데이터 = (Ciphertext || tag). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 */
uint8_t INTERNAL * dot2_AES_CCM_128_Encrypt(
  const uint8_t *plaintext,
  size_t plaintext_len,
  const struct Dot2AESKey *key,
  const struct Dot2AESNonce *nonce,
  int *ret)
{
  int len;
  uint8_t *encrypted = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t *ciphertext_and_tag = (uint8_t *)malloc(plaintext_len + DOT2_AES_128_TAG_LEN);
  *ret = -kDot2Result_FailAESEncrypt;
  if ((ciphertext_and_tag) &&
      (ctx = EVP_CIPHER_CTX_new()) && // 컨텍스트 초기화
      (EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1) && // 암호화 동작 초기화
      (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, DOT2_AES_128_NONCE_LEN, NULL) == 1) && // Nonce(IV) 길이 설정
      (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, DOT2_AES_128_TAG_LEN, NULL) == 1) && // Tag 길이 설정
      (EVP_EncryptInit_ex(ctx, NULL, NULL, key->octs, nonce->octs) == 1) && // 암호화키와 Nonce 설정
      (EVP_EncryptUpdate(ctx, NULL, &len, NULL, (int)plaintext_len) == 1) && // 평문 길이 설정
      (EVP_EncryptUpdate(ctx, ciphertext_and_tag, &len, plaintext, (int)plaintext_len) == 1) && // 암호화 수행 (len에 암호문의 길이가 저장됨)
      (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, DOT2_AES_128_TAG_LEN, ciphertext_and_tag + len) == 1)) { // Tag 획득
    encrypted = ciphertext_and_tag;
    *ret = len + DOT2_AES_128_TAG_LEN;
  } else {
    if (ciphertext_and_tag) {
      free(ciphertext_and_tag);
      ciphertext_and_tag = NULL;
    }
  }
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return encrypted;
}


/**
 * 데이터를 암호화하고, 암호화 대칭키를 ECIES 암호화한다.
 * @param[in] data 암호화할 데이터 바이트열
 * @param[in] data_len data의 길이
 * @param[in] k AES 암호화 키 바이트열
 * @param[in] n AES nonce N 바이트열
 * @param[in] v 송신자 임시(ephemeral) 개인키 바이트열
 * @param[in] p1 키파생함수(KDF2)에 입력되는 해시
 * @param[in] R 수신자 공개키 바이트열
 * @param[out] C 암호화된 AES 키가 저장될 구조체 포인터
 * @param[out] T 생성된 Authentication tag가 저장될 구조체 포인터
 * @param[out] ciphertext_and_tag_len 암호돠된 데이터 바이트열의 길이가 반환될 변수 포인터. 동작 실패시 저장되지 않는다.
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 암호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 암호화된 데이터(Ciphertext || tag 형식을 갖는다). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_EncryptDataAndKey(
  const uint8_t *data,
  size_t data_len,
  const struct Dot2AESKey *k,
  const struct Dot2AESNonce *n,
  const struct Dot2ECPrivateKey *v,
  const struct Dot2SHA256 *p1,
  const struct Dot2ECPublicKey *R,
  struct Dot2AESKey *C,
  struct Dot2AESAuthTag *T,
  int *ret)
{
  /*
   * AES 키를 ECIES 암호화하고 데이터를 AES 암호화한다.
   */
  uint8_t *encrypted = NULL;
  *ret = dot2_ECIES_Encrypt(v, k, p1, R, C, T); // AES 키 암호화
  if (*ret == kDot2Result_Success) {
    encrypted = dot2_AES_CCM_128_Encrypt(data, data_len, k, n, ret); // 데이터 암호화
  }
  return encrypted;
}


/**
 * @brief 데이터를 암호화한다.
 * @param[in] data 암호화할 데이터 바이트열
 * @param[in] data_len 암호화할 데이터 바이트열의 길이
 * @param[in] key_input 키파생함수(KDF2) 입력 데이터 바이트열로써 다음 중 하나.
 *                      (1) 수신자인증서 바이트열 or (2) Ieee1609Dot2Data 바이트열 or (3) 빈문자열(NULL 전달시)
 * @param[in] key_input_size 키 파생함수(KDF2) 입력 데이터 바이트열의 길이 (key_input=NULL일 경우 무의미하다)
 * @param[in] pubkey_r 상대방 공개키 바이트열
 * @param[out] V 생성된 비압축형식 임시(ephemeral) 공개키 바이트열이 저장될 구조체 포인터
 * @param[out] C 암호화된 AES 공개키 바이트열이 저장될 구조체 포인터
 * @param[out] T 생성된 Authentication tag 바이트열이 저장될 구조체 포인터
 * @param[out] nonce 생성된 nonce 바이트열이 저장될 구조체 포인터
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 암호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 암호화된 데이터(Ciphertext || tag 형식을 갖는다). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_EncryptData_1(
  const uint8_t *data,
  size_t data_len,
  const uint8_t *key_input,
  size_t key_input_size,
  struct Dot2ECPublicKey *pubkey_r,
  struct Dot2ECPublicKey *V,
  struct Dot2AESKey *C,
  struct Dot2AESAuthTag *T,
  struct Dot2AESNonce *nonce,
  int *ret)
{
  /*
   * KDF2 입력인 p1을 계산한다
   */
  struct Dot2SHA256 p1;
  if (!key_input ||
      (key_input_size == 0)) {
    key_input = NULL;
    key_input_size = 0;
  }
  SHA256(key_input, key_input_size, p1.octs);

  return dot2_EncryptData_2(data, data_len, &p1, pubkey_r, V, C, T, nonce, ret);
}


/**
 * @brief 데이터를 암호화한다.
 * @param[in] data 암호화할 데이터 바이트열
 * @param[in] data_len 암호화할 데이터 바이트열의 길이
 * @param[in] key_input_h p1 키파생함수(KDF2)에 입력되는 해시
 * @param[in] pubkey_r 상대방 공개키 바이트열
 * @param[out] V 생성된 비압축형식 임시(ephemeral) 공개키 바이트열이 저장될 구조체 포인터
 * @param[out] C 암호화된 AES 공개키 바이트열이 저장될 구조체 포인터
 * @param[out] T 생성된 Authentication tag 바이트열이 저장될 구조체 포인터
 * @param[out] nonce 생성된 nonce 바이트열이 저장될 구조체 포인터
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 암호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 암호화된 데이터(Ciphertext || tag 형식을 갖는다). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_EncryptData_2(
  const uint8_t *data,
  size_t data_len,
  const struct Dot2SHA256 *key_input_h,
  struct Dot2ECPublicKey *pubkey_r,
  struct Dot2ECPublicKey *V,
  struct Dot2AESKey *C,
  struct Dot2AESAuthTag *T,
  struct Dot2AESNonce *nonce,
  int *ret)
{
  /*
   * AES 키, nonce를 랜덤하게 생성한다.
   */
  RAND_status();
  struct Dot2AESKey aes_key;
  RAND_bytes(aes_key.octs, sizeof(aes_key.octs));
  RAND_bytes(nonce->octs, DOT2_AES_128_NONCE_LEN);

  /*
   * 임시(ephemeral) 키쌍을 생성하고, 데이터 및 키를 암호화한다.
   */
  struct Dot2ECKeyPairOcts key_pair; // 임시 키쌍이 저장될 구조체
  memset(&key_pair, 0, sizeof(key_pair));
  uint8_t *encrypted = NULL;
  *ret = dot2_ossl_GenerateECKeyPairOcts(&key_pair);
  if (*ret == kDot2Result_Success) {
    encrypted = dot2_EncryptDataAndKey(data,
                                       data_len,
                                       &aes_key,
                                       nonce,
                                       &(key_pair.priv_key),
                                       key_input_h,
                                       pubkey_r,
                                       C,
                                       T,
                                       ret);
    if (encrypted) {
      memcpy(V, &(key_pair.pub_key), sizeof(struct Dot2ECPublicKey)); // V를 반환한다.
    }
  }

  return encrypted;
}


/**
 * @brief AES-CCM-128 복호화를 수행한다.
 * @param[in] ciphertext_and_tag "Ciphertext || Tag" 바이트열 (Null 전달 불가 - tag 값 접근 시 segmentation fault 발생)
 * @param[in] ciphertext_and_tag_len ciphertext_and_tag 바이트열의 길이
 * @param[in] key 복호화 키
 * @param[in] nonce Nonce N
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 복호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 복호화된 데이터(plaintext). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_AES_CCM_128_Decrypt(
  uint8_t *ciphertext_and_tag,
  size_t ciphertext_and_tag_len,
  const struct Dot2AESKey *key,
  const struct Dot2AESNonce *nonce,
  int *ret)
{
  EVP_CIPHER_CTX *ctx = NULL;
  uint8_t *decrypted = NULL;
  int len, ciphertext_len = (int)ciphertext_and_tag_len - DOT2_AES_128_TAG_LEN;
  int plaintext_len = ciphertext_len;
  uint8_t *ciphertext = ciphertext_and_tag;
  uint8_t *tag = ciphertext_and_tag + ciphertext_len;
  uint8_t *plaintext = (uint8_t *)malloc(plaintext_len);
  *ret = -kDot2Result_FailAESDecrypt;
  if ((plaintext) &&
      (ctx = EVP_CIPHER_CTX_new()) && // 컨텍스트 초기화
      (EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1) && // 복호화 동작 초기화
      (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, DOT2_AES_128_NONCE_LEN, NULL) == 1) && // Nonce(IV) 길이 설정
      (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, DOT2_AES_128_TAG_LEN, tag) == 1) && // Tag 설정
      (EVP_DecryptInit_ex(ctx, NULL, NULL, key->octs, nonce->octs) == 1) && // Key 및 Nonce 설정
      (EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len) == 1) && // 암호문 길이 설정
      (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) == 1)) { // 복호화 수행
    decrypted = plaintext;
    *ret = plaintext_len;
  } else {
    if (plaintext) {
      free(plaintext);
    }
  }
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return decrypted;
}


/**
 * 암호화된 대칭키를 ECIES 복호화하고, 암호화 데이터를 복호화한다.
 * @param[in] ciphertext_and_tag 암호화된 데이터 및 태그 바이트열
 * @param[in] ciphertext_and_tag_len ciphertext_and_tag 길이
 * @param[in] n AES nonce N 바이트열
 * @param[in] C 암호화된 AES 키 바이트열
 * @param[in] V 송신자의 임시(ephemeral) 공개키 바이트열 (비압축형식)
 * @param[in] T Authentication tag 바이트열
 * @param[in] r 수신자의 개인키 바이트열
 * @param[in] p1 키파생함수(KDF2)에 입력되는 해시
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 복호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 복호화된 데이터(plaintext). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_DecryptDataAndKey(
  uint8_t *ciphertext_and_tag,
  size_t ciphertext_and_tag_len,
  const struct Dot2AESNonce *n,
  const struct Dot2AESKey *C,
  const struct Dot2ECPublicKey *V,
  const struct Dot2AESAuthTag *T,
  const struct Dot2ECPrivateKey *r,
  const struct Dot2SHA256 *p1,
  int *ret)
{
  /*
   * AES 키를 복호화하고 데이터를 복호화한다.
   */
  uint8_t *decrypted = NULL;
  struct Dot2AESKey dec_aes_key;
  *ret = dot2_ECIES_Decrypt(V, C, T, r, p1, &dec_aes_key); // AES 키 복호화
  if (*ret == kDot2Result_Success) {
    decrypted = dot2_AES_CCM_128_Decrypt(ciphertext_and_tag, ciphertext_and_tag_len, &dec_aes_key, n, ret); // 데이터 복호화
  }
  return decrypted;
}


/**
 * @brief 데이터를 복호화한다.
 * @param[in] data 복호화할 데이터 바이트열. (Ciphertext || tag) 형식을 가져야 한다.
 * @param[in] data_len 복호화할 데이터 바이트열의 길이 (DOT2_AES_CCM_128_TAG_LEN 이상의 길이를 가져야 한다)
 * @param[in] key_input 키파생함수(KDF2) 입력 데이터 바이트열로써 다음 중 하나.
 *                      (1) 수신자인증서 바이트열 or (2) Ieee1609Dot2Data 바이트열 or (3) 빈문자열(NULL 전달시)
 * @param[in] key_input_size 키 파생함수(KDF2) 입력 데이터 바이트열의 길이 (key_input=NULL일 경우 무의미하다)
 * @param[in] privkey 내 개인키 바이트열
 * @param[in] V 임시(ephemeral) 공개키 바이트열
 * @param[in] C 암호화된 AES 공개키 바이트열
 * @param[in] T Authentication tag 바이트열
 * @param[in] nonce nonce 바이트열
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 복호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 복호화된 데이터(plaintext). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_DecryptData_1(
  uint8_t *data,
  size_t data_len,
  const uint8_t *key_input,
  size_t key_input_size,
  const struct Dot2ECPrivateKey *privkey,
  const struct Dot2ECPublicKey *V,
  const struct Dot2AESKey *C,
  const struct Dot2AESAuthTag *T,
  const struct Dot2AESNonce *nonce,
  int *ret)
{
  /*
   * KDF2 입력인 p1을 계산한다
   */
  struct Dot2SHA256 p1;
  if (!key_input ||
      (key_input_size == 0)) {
    key_input = NULL;
    key_input_size = 0;
  }
  SHA256(key_input, key_input_size, p1.octs);

  /*
   * 임시 공개키 V가 압축형식일 경우, 비압축형식으로 변경한다.
   */
  const struct Dot2ECPublicKey *V_in;
  struct Dot2ECPublicKey V_uncomp;
  if (V->u.point.form != kDot2ECPointForm_Uncompressed) {
    EC_KEY *eck_V = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(V, &V_uncomp, ret);
    if (eck_V == NULL) {
      *ret = -kDot2Result_OSSL_ReconverY;
      return NULL;
    }
    EC_KEY_free(eck_V);
    V_in = &V_uncomp;
  } else {
    V_in = V;
  }

  /*
   * 데이터를 복호화한다.
   */
  return dot2_DecryptDataAndKey(data, data_len, nonce, C, V_in, T, privkey, &p1, ret);
}


/**
 * @brief 데이터를 복호화한다.
 * @param[in] data 복호화할 데이터 바이트열. (Ciphertext || tag) 형식을 가져야 한다.
 * @param[in] data_len 복호화할 데이터 바이트열의 길이 (DOT2_AES_CCM_128_TAG_LEN 이상의 길이를 가져야 한다)
 * @param[in] key_input_h 키파생함수(KDF2)에 입력되는 해시
 * @param[in] privkey 내 개인키 바이트열
 * @param[in] V 임시(ephemeral) 공개키 바이트열
 * @param[in] C 암호화된 AES 공개키 바이트열
 * @param[in] T Authentication tag 바이트열
 * @param[in] nonce nonce 바이트열
 * @param[out] ret 결과가 반환될 변수 포인터 (성공 시: 반환된 복호화데이터의 길이, 실패: 음수(-Dot2ResultCode))
 * @return 복호화된 데이터(plaintext). 동적할당된 정보이므로 사용 후 free() 해 주어야 한다.
 * @retval NULL: 실패
 */
uint8_t INTERNAL * dot2_DecryptData_2(
  uint8_t *data,
  size_t data_len,
  const struct Dot2SHA256 *key_input_h,
  const struct Dot2ECPrivateKey *privkey,
  const struct Dot2ECPublicKey *V,
  const struct Dot2AESKey *C,
  const struct Dot2AESAuthTag *T,
  const struct Dot2AESNonce *nonce,
  int *ret)
{
  /*
   * 데이터를 복호화한다.
   */
  return dot2_DecryptDataAndKey(data, data_len, nonce, C, V, T, privkey, key_input_h, ret);
}
