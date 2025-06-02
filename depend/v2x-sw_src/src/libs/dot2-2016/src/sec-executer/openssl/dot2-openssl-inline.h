/** 
  * @file 
  * @brief Openssl 기반 인라인 함수 정의
  * @date 2022-07-02 
  * @author gyun 
  */


#ifndef V2X_SW_DOT2_OPENSSL_INLINE_H
#define V2X_SW_DOT2_OPENSSL_INLINE_H


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

// 라이브러리 의존 헤더 파일
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-defines.h"


/**
 * @brief 서명 계산에 입력되는 해시값을 계산한다. e = H(Hash(tbs) || Hash(signer_id))
 * @param[in] tbs_h 서명 검증을 위한 해시입력값으로 사용될 ToBeSigned 데이터 해시
 * @param[in] signer_h 서명인증서 해시 (NULL 가능)
 * @param[out] h 계산된 해시값이 저장될 구조체 포인터
 */
static inline void dot2_ossl_CalculateSignatureHashInput_H(
  const struct Dot2SHA256 *tbs_h,
  const struct Dot2SHA256 *signer_h,
  struct Dot2SHA256 *h)
{
  uint8_t tmp[DOT2_SHA_256_LEN * 2];
  memcpy(tmp, tbs_h->octs, DOT2_SHA_256_LEN);
  if (signer_h) {
    memcpy(tmp + DOT2_SHA_256_LEN, signer_h->octs, DOT2_SHA_256_LEN);
  } else {
    SHA256(NULL, 0, tmp + DOT2_SHA_256_LEN);
  }
  SHA256(tmp, sizeof(tmp), h->octs);
}


/**
 * @brief 서명 계산에 입력되는 해시값을 계산한다. e = H(Hash(tbs) || Hash(signer_id))
 * @param[in] tbs 서명 검증을 위한 해시입력값으로 사용될 ToBeSigned 데이터(ToBeSignedData 또는 ToBeSignedCert)
 * @param[in] tbs_size ToBeSigned 데이터의 크기
 * @param[in] signer_h 서명인증서 해시 (NULL 가능)
 * @param[out] h 계산된 해시값이 저장될 구조체 포인터
 */
static inline void dot2_ossl_CalculateSignatureHashInput(
  const uint8_t *tbs,
  size_t tbs_size,
  const struct Dot2SHA256 *signer_h,
  struct Dot2SHA256 *h)
{
  struct Dot2SHA256 tbs_h;
  SHA256(tbs, tbs_size, tbs_h.octs);
  dot2_ossl_CalculateSignatureHashInput_H(&tbs_h, signer_h, h);
}


/**
 * @brief Implicit 인증서 키 재구성 연산에 사용되는 해시입력을 계산한다.
 * @param[in] tbs_cert_h 인증서 내 ToBeSignedCertificate 영역에 대한 해시
 * @param[in] issuer_h 상위인증서에 대한 해시
 * @param[out] h 계산된 해시가 저장될 구조체 포인터
 *
 * 해시입력 = H(CertU) = H( tbs_cert_h || issuer_h )
 */
static inline void dot2_ossl_CalculateKeyReconstructionHashInput_2(
  const uint8_t *tbs,
  Dot2CertSize tbs_size,
  const struct Dot2SHA256 *issuer_h,
  struct Dot2SHA256 *h)
{
  uint8_t tmp[DOT2_SHA_256_LEN * 2];
  SHA256(tbs, tbs_size, tmp); // H(ToBeSignedCert) 계산
  memcpy(tmp + DOT2_SHA_256_LEN, issuer_h->octs, DOT2_SHA_256_LEN); // H(ToBeSignedCert) || H(Issuer)
  SHA256(tmp, sizeof(tmp), h->octs); // H( H(ToBeSignedCert) || H(Issuer) )
}


/**
 * @brief Implicit 형식의 서명자(인증서) 공개키 재구성 시 입력되는 해시값을 계산한다.
 * @param[in] signer 서명자인증서 바이트열
 * @param[in] signer_size 서명자인증서 바이트열의 길이
 * @param[in] issuer_h 서명인증서의 상위인증서 해시 (현재 pca/aca이다)
 * @param[out] h 계산된 해시값이 저장될 구조체 포인터
 *
 * 해시입력 = H(CertU) = H( tbs_cert_h || issuer_h )
 */
static inline void dot2_ossl_CalculateKeyReconstructionHashInput_1(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  const struct Dot2SHA256 *issuer_h,
  struct Dot2SHA256 *h)
{
  const uint8_t *tbs = DOT2_GET_ISSUER_SIGNED_CERT_TBS(cert);
  Dot2CertSize tbs_size = DOT2_GET_ISSUER_SIGNED_IMPLICIT_CERT_TBS_SIZE(cert_size);
  dot2_ossl_CalculateKeyReconstructionHashInput_2(tbs, tbs_size, issuer_h, h);
}


/**
 * @brief Implicit 인증서 키 재구성 연산에 사용되는 해시입력을 계산한다.
 * @param[in] tbs_cert_h 인증서 내 ToBeSignedCertificate 영역에 대한 해시
 * @param[in] issuer_h 상위인증서에 대한 해시
 * @param[out] h 계산된 해시가 저장될 구조체 포인터
 *
 * 해시입력 = H(CertU) = H( tbs_cert_h || issuer_h )
 */
static inline void dot2_ossl_CalculateKeyReconstructionHashInput_3(
  const struct Dot2SHA256 *tbs_cert_h,
  const struct Dot2SHA256 *issuer_h,
  struct Dot2SHA256 *h)
{
  uint8_t tmp[DOT2_SHA_256_LEN * 2];
  memcpy(tmp, tbs_cert_h->octs, sizeof(tbs_cert_h->octs));
  memcpy(tmp + DOT2_SHA_256_LEN, issuer_h->octs, sizeof(issuer_h->octs));
  SHA256(tmp, sizeof(tmp), h->octs);
}


/**
 * @brief BIGNUN 형식의 개인키로부터 개인키 바이트열을 획득한다.
 * @param[in] bn_priv_key BIGNUM 형식 개인키
 * @param[out] priv_key 개인키바이트열이 저장될 구조체 포인터
 * @retval true: 성공
 * @retval false: 실패
 */
static inline bool dot2_ossl_GetPrivKeyOctsFromBIGNUM(const BIGNUM *bn_priv_key, struct Dot2ECPrivateKey *priv_key)
{
  return (BN_bn2binpad(bn_priv_key, priv_key->octs, sizeof(priv_key->octs)) == sizeof(priv_key->octs)) ? true : false;
}


/**
 * @brief 서명용 개인키 재구성을 위한 연산값인 x = (i,j) 값을 구한다. (CAMP wiki 문서에는 x 대신 l 로 표현되어 있음)
 * @param[in] i 인증서 i 값
 * @param[in] j 인증서 j 값
 * @param[out] x x 값이 저장될 버퍼. DOT2_AES_128_LEN 의 길이를 가진다.
 */
static inline void dot2_ossl_derive_signing_x(uint32_t i, uint32_t j, uint8_t *x)
{
  memset(x, 0, DOT2_AES_128_LEN);
  *(uint32_t *)(x + 4) = htonl(i);
  *(uint32_t *)(x + 8) = htonl(j);
}


/**
 * @brief 암호화용 개인키 재구성을 위한 연산값인 x = (i,j) 값을 구한다. (CAMP wiki 문서에는 x 대신 l 로 표현되어 있음)
 * @param[in] i 인증서 i 값
 * @param[in] j 인증서 j 값
 * @param[out] x x 값이 저장될 버퍼. DOT2_AES_128_LEN 의 길이를 가진다.
 */
static inline void dot2_ossl_derive_encryption_x(uint32_t i, uint32_t j, uint8_t *x)
{
  memset(x, 0xff, 4);
  *(uint32_t *)(x + 4) = htonl(i);
  *(uint32_t *)(x + 8) = htonl(j);
  memset(x + 12, 0, 4);
}


/**
 * @brief AES ECB 암호화를 수행한다.
 * @param[in] enc_key 암호화용 키 (DOT2_AES_128_LEN의 길이를 가진다)
 * @param[in] ptext 암호화할 평문 바이트열 (DOT2_AES_128_LEN의 길이를 가진다)
 * @param[out] ctext 암호화문이 저장될 버퍼 (DOT2_AES_128_LEN의 길이를 가진다)
 * @retval true: 성공
 * @retval false: 실패
 */
static inline bool dot2_ossl_AESECBEncrypt(const uint8_t *enc_key, const uint8_t *ptext, uint8_t *ctext)
{
  bool ret = false;
  AES_KEY aes_key;
  memset(&aes_key, 0, sizeof(aes_key));
  if (AES_set_encrypt_key(enc_key, DOT2_AES_128_LEN * 8, &aes_key) == 0) {
    AES_ecb_encrypt(ptext, ctext, &aes_key, AES_ENCRYPT);
    ret = true;
  }
  return ret;
}


/**
 * @brief 두 배열의 XOR 값을 계산한다.
 * @param[in] i_value XOR 계산 입력 배열 1
 * @param[in] len 배열 길이
 * @param[in,out] io_value XOR 계산 입력 및 출력 배열
 */
static inline void dot2_XOR(const uint8_t *i_value, int len, uint8_t *io_value)
{
  for (int i = 0; i < len; i++) {
    *(io_value + i) = *(io_value + i) ^ *(i_value + i);
  }
}


/**
 * @brief fint(k,x) 방정식을 계산한다. (서명용/암호화용 키쌍 확장에 관련된 방정식)
 * @param[in] k k 값 (DOT2_AES_128_LEN의 길이를 가진다)
 * @param[in] x x 값 (DOT2_AES_128_LEN의 길이를 가진다)
 * @param[out] res 계산값이 저장될 버퍼. DOT2_AES_128_LEN * 3 의 길이를 가진다.
 * @retval true: 성공
 * @retval false: 실패
 *
 * fint(k,x) 방정식은 다음과 같이 계산된다. \n
 *  - (AES(k, x+1) XOR (x+1)) || (AES(k, x+2) XOR (x+2)) || (AES(k, x+3) XOR (x+3))
 */
static inline bool dot2_ossl_f_int_k_x(const uint8_t *k, uint8_t *x, uint8_t *res)
{
  bool ret = false;
  uint8_t tmp[DOT2_AES_128_LEN];
  *(x + 15) = 1;
  if (dot2_ossl_AESECBEncrypt(k, x, tmp)) {
    dot2_XOR(x, DOT2_AES_128_LEN, tmp);
    memcpy(res, tmp, DOT2_AES_128_LEN);
    *(x + 15) = 2;
    if (dot2_ossl_AESECBEncrypt(k, x, tmp)) {
      dot2_XOR(x, DOT2_AES_128_LEN, tmp);
      memcpy(res + DOT2_AES_128_LEN, tmp, DOT2_AES_128_LEN);
      *(x + 15) = 3;
      if (dot2_ossl_AESECBEncrypt(k, x, tmp)) {
        dot2_XOR(x, DOT2_AES_128_LEN, tmp);
        memcpy(res + (DOT2_AES_128_LEN * 2), tmp, DOT2_AES_128_LEN);
        ret = true;
      }
    }
  }
  return ret;
}


/**
 * @brief AES 키를 생성한다.
 * @param[out] aes_key 생성된 키가 저장될 구조체 포인터
 */
static inline void dot2_ossl_GenerateAESKey(struct Dot2AESKey *aes_key)
{
  RAND_status();
  RAND_bytes(aes_key->octs, sizeof(aes_key->octs));
}


#endif //V2X_SW_DOT2_OPENSSL_INLINE_H
