/** 
  * @file 
  * @brief 
  * @date 2022-04-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief ECDH 기능 구현 함수. A의 개인키와 B의 공개키를 이용하여 Shared secret 값을 생성하여 X 좌표를 반환한다.
 * @param[in] privkey_a A의 개인키 바이트열
 * @param[in] pubkey_B B의 공개키 바이트열
 * @param[out] ss_x 생성된 Shared secret의 X좌표 바이트열이 저장될 버퍼 (DOT2_EC_256_KEY_LEN 이상의 길이를 가져야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * Shared secret ss = privkey_a * pubkey_B
 */
int INTERNAL dot2_ECDH(const struct Dot2ECPrivateKey *privkey_a, const struct Dot2ECPublicKey *pubkey_B, uint8_t *ss_x)
{
  EC_GROUP *ec_grp = g_dot2_mib.sec_executer.ossl.ecg;
  BN_CTX *bn_ctx = NULL;
  EC_POINT *ecp_ss = NULL;
  EC_POINT *ecp_pubkey_B = NULL;
  BIGNUM *bn_privkey_a = NULL;

  int ret = -kDot2Result_FailECDH;
  size_t pubkey_len = DOT2_EC_256_PUB_KEY_LEN;
  uint8_t ss[DOT2_EC_256_PUB_KEY_LEN];
  if ((bn_ctx = BN_CTX_new()) && // BIGNUM 컨텍스트 생성
      (ecp_ss = EC_POINT_new(ec_grp)) && // Shared secret이 저장될 EC point 생성
      (ecp_pubkey_B = EC_POINT_new(ec_grp)) && // B 공개키가 저장될 EC point 생성
      (bn_privkey_a = BN_bin2bn(privkey_a->octs, DOT2_EC_256_KEY_LEN, NULL)) && // a 개인키 바이트열을 BIGNUM 형식으로 변환
      (EC_POINT_oct2point(ec_grp, ecp_pubkey_B, pubkey_B->u.octs, pubkey_len, bn_ctx) == 1) && // B 공개키를 EC_POINT 형식으로 변환
      (EC_POINT_mul(ec_grp, ecp_ss, NULL, ecp_pubkey_B, bn_privkey_a, bn_ctx) == 1) && // ss = a * B 계산
      (EC_POINT_point2oct(ec_grp, ecp_ss, POINT_CONVERSION_UNCOMPRESSED, ss, pubkey_len, bn_ctx) == pubkey_len)) { // ss를 바이트열 형식으로 변환
    memcpy(ss_x, ss + 1, DOT2_EC_256_KEY_LEN); // X 좌표를 반환 버퍼에 복사
    ret = kDot2Result_Success;
  }

  if (bn_privkey_a) { BN_free(bn_privkey_a); }
  if (ecp_pubkey_B) { EC_POINT_free(ecp_pubkey_B); }
  if (ecp_ss) { EC_POINT_free(ecp_ss); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  return ret;
}


/**
 * IEEE 1363a 표준의 KDF2 기능 구현 함수
 * @param[in] ss_x Shared secret X 좌표 바이트열 (Null 전달 불가)
 * @param[in] ss_x_len ss_x 바이트열의 길이
 * @param[in] kdp Key derivation parameter 바이트열
 * @param[in] kdp_len kdp 바이트열의 길이
 * @param[in] desired_len 도출할 키의 길이 (바이트단위)
 * @return desired_len보다 크면서 32바이트(해시길이) 배수의 길이를 갖는 도출된 키 스트림 (동적할당된 데이터이므로 사용 후 free() 해 주어야 한다)
 * @retval NULL: 실패
 *
 * Derived key stream = SHA256( SSx || 1 || KDP ) || SHA256( SSx || 2 || KDP) || ....
 * 도출된 키 스트림의 길이가 desired_len 변수값 이상이 될때까지 해시 블럭을 연결한다.
 */
uint8_t INTERNAL *
dot2_KDF2_SHA256(const uint8_t *ss_x, size_t ss_x_len, const uint8_t *kdp, size_t kdp_len, size_t desired_len)
{
  /*
   * 연결할 해시 블럭의 수를 계산한다. (연결되는 해시 블럭의 길이가 desired_len 길이보다 크도록)
   */
  size_t block_num = (desired_len / DOT2_SHA_256_LEN);
  if (desired_len % DOT2_SHA_256_LEN) {
    block_num++;
  }

  /*
   * 키 스트림(=연결된 해시블럭)을 도출한다.
   */
  uint8_t *h_input;
  uint8_t *derived_key_stream = (uint8_t *)malloc(block_num * DOT2_SHA_256_LEN);
  if (derived_key_stream) {
    // 해시 블럭 입력 데이터 길이 - SS || counter || (KDP)
    size_t h_input_len = ss_x_len + sizeof(uint32_t);
    h_input_len += kdp_len;
    // 계산된 해시 블럭 연결
    for (uint32_t counter = 1; counter < block_num + 1; counter++) {
      h_input = malloc(h_input_len);
      if (h_input) {
        memcpy(h_input, ss_x, ss_x_len);
        *(uint32_t *)(h_input + ss_x_len) = htonl(counter);
        memcpy(h_input + ss_x_len + sizeof(uint32_t), kdp, kdp_len);
        SHA256(h_input, h_input_len, derived_key_stream + (DOT2_SHA_256_LEN * (counter - 1)));
        free(h_input);
      } else {
        free(derived_key_stream);
        return NULL;
      }
    }
  }
  return derived_key_stream;
}


/**
 * @brief MAC1(SHA-256) 기능 구현 함수. Message Authentication Code Tag를 생성하여 반환한다.
 * @param[in] key 키
 * @param[in] key_len 키 길이
 * @param[in] msg 메시지
 * @param[in] msg_len 메시지의 길이
 * @param[out] auth_tag 생성된 Tag 값이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_HMAC_SHA256(
  const uint8_t *key,
  size_t key_len,
  const uint8_t *msg,
  size_t msg_len,
  struct Dot2AESAuthTag *auth_tag)
{
  int ret = -kDot2Result_FailHMAC;
  unsigned int h_output_len;
  uint8_t h_output[DOT2_SHA_256_LEN];
  if (HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, h_output, &h_output_len) != NULL) {
    memcpy(auth_tag->octs, h_output, DOT2_AUTH_TAG_LEN);
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief ECIES 암호화 기능 구현 함수. v, k, p1, R을 이용하여 V, C, T를 생성한다.
 * @param[in] v 송신자의 임시(ephemeral) 개인키
 * @param[in] k 암호화될 AES 키
 * @param[in] p1 키파생함수(KDF2)에 입력되는 해시
 * @param[in] R 수신자의 공개키
 * @param[out] C 암호화된 AES 키가 저장될 구조체 포인터
 * @param[out] T 생성된 Authentication tag가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ECIES_Encrypt(
  const struct Dot2ECPrivateKey *v,
  const struct Dot2AESKey *k,
  const struct Dot2SHA256 *p1,
  const struct Dot2ECPublicKey *R,
  struct Dot2AESKey *C,
  struct Dot2AESAuthTag *T)
{
  /*
   * 1) shared secret을 생성한다 (ss = v * R)
   * 2) 키 스트림을 생성한다.
   *   생성된 키 스트림의 앞 16바이트(=k_enc)는 AES 키를 암호화하는데 쓰인다.
   *   생성된 키 스트림의 뒤 32바이트(=k_mac)는 Authentication tag를 생성하는데 쓰인다.
   * 3) AES 키를 암호화한다 (C = k ^ k_enc)
   * 4) Authentication tag를 구한다.
   */
  // shared secret 생성
  uint8_t ss_x[DOT2_EC_256_KEY_LEN];
  int ret = dot2_ECDH(v, R, ss_x);
  if (ret == kDot2Result_Success) {
    ret = -kDot2Result_FailKDF2;
    // 키 스트림 생성
    uint8_t *key_stream = dot2_KDF2_SHA256(ss_x, sizeof(ss_x), p1->octs, DOT2_SHA_256_LEN, DOT2_AES_128_LEN + DOT2_SHA_256_LEN);
    if (key_stream) {
      // AES 키 암호화
      uint8_t *k_enc = key_stream;
      for (int i = 0; i < DOT2_AES_128_LEN; i++) {
        *(C->octs + i) = *(k->octs + i) ^ *(k_enc + i);
      }
      // Authentication tag를 구한다.
      uint8_t *k_mac = key_stream + DOT2_AES_128_LEN;
      ret = dot2_HMAC_SHA256(k_mac, DOT2_SHA_256_LEN, C->octs, DOT2_AES_128_LEN, T);
      free(key_stream);
    }
  }
  return ret;
}


/**
 * @brief ECIES 복호화 기능 구현 함수. V, C, T, r, p1을 이용하여 k를 복호화한다.
 * @param[in] V 송신자의 임시(ephemeral) 공개키
 * @param[in] C 암호화된 AES 키
 * @param[in] T Authentication tag
 * @param[in] r 수신자의 개인키
 * @param[in] p1 키파생함수(KDF2)에 입력되는 해시
 * @param[out] k 복호화된 AES 키가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-DotResultCode): 실패
 */
int INTERNAL dot2_ECIES_Decrypt(
  const struct Dot2ECPublicKey *V,
  const struct Dot2AESKey *C,
  const struct Dot2AESAuthTag *T,
  const struct Dot2ECPrivateKey *r,
  const struct Dot2SHA256 *p1,
  struct Dot2AESKey *k)
{
  /*
   * 1) shared secret을 생성한다. (ss = r * V)
   * 2) 키 스트림을 생성한다.
   *   생성된 키 스트림의 앞 16바이트(=k_enc)는 AES 키를 암호화하는데 쓰인다.
   *   생성된 키 스트림의 뒤 32바이트(=k_mac)는 Authentication tag를 생성하는데 쓰인다.
   * 3) Authentication tag를 구해서 전달된 tag(T)와 비교한다 - 동일하지 않으면 실패를 반환한다.
   * 4) AES 키를 복호화한다 (k = C ^ k_enc)
   */
  uint8_t ss_x[DOT2_EC_256_KEY_LEN];
  // shared secret 생성
  int ret = dot2_ECDH(r, V, ss_x);
  if (ret == kDot2Result_Success) {
    ret = -kDot2Result_FailKDF2;
    // 키 스트림 생성
    uint8_t *key_stream = dot2_KDF2_SHA256(ss_x, sizeof(ss_x), p1->octs, DOT2_SHA_256_LEN, DOT2_AES_128_LEN + DOT2_SHA_256_LEN);
    if (key_stream) {
      // Authentication tag 계산
      struct Dot2AESAuthTag tag;
      uint8_t *k_mac = key_stream + DOT2_AES_128_LEN;
      ret = dot2_HMAC_SHA256(k_mac, DOT2_SHA_256_LEN, C->octs, DOT2_AES_128_LEN, &tag);
      if (ret == kDot2Result_Success) {
        // Authentication tag 비교
        if (memcmp(tag.octs, T->octs, DOT2_AUTH_TAG_LEN) == 0) {
          // AES 키 복호화
          uint8_t *k_enc = key_stream;
          for (int i = 0; i < DOT2_AES_128_LEN; i++) {
            *(k->octs + i) = *(C->octs + i) ^ *(k_enc + i);
          }
        } else {
          Err("Fail to ECIES decrypt - different auth tag\n");
          ret = -kDot2Result_DifferentECIESAuthenticationTag;
        }
      }
      free(key_stream);
    }
  }
  return ret;
}
