/** 
  * @file 
  * @brief 서명검증용 버터플라이 키 재구성 관련 구현
  * @date 2022-08-04 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <arpa/inet.h>

// 라이브러리 의존 헤더 파일
#include "openssl/aes.h"
#include "openssl/bn.h"
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-openssl-inline.h"


/**
 * @brief 서명용 개인키/공개키를 재구성하는데 사용되는 Cocoon 키쌍을 만든다.
 * @param[in] i 인증서 i 값. 예: 인증서 파일명 중 앞 숫자 (8E_0.cert 중 8E)
 * @param[in] j 인증서 j 값. i 주 내에서의 인증서 순서 (0~19). 예: 인증서 파일명 중 뒤 숫자 (8E_0.cert 중 0)
 * @param[in] exp_key 확장함수 키
 * @param[in] seed_priv 시드개인키 (caterpillar 개인키)
 * @param[out] key_pair Cocoon 키쌍이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 서명용 Coccon 개인키/공개키는 다음과 같이 계산된다. \n
 *  - 재구성용 개인키 bn = a + f1(i,j) \n
 *  - 재구성용 공개키 Bn = A + f1(i,j) * G \n
 *      a : seed_priv (from dwnl_sgn.priv) \n
 *      A : seed_pub = seed_priv * G \n
 *      G : ECC curve generator
 */
int INTERNAL dot2_ossl_MakeSigningCocoonKeyPair(
  uint32_t i,
  uint32_t j,
  const struct Dot2AESKey *exp_key,
  const struct Dot2ECPrivateKey *seed_priv,
  struct Dot2ECKeyPairOcts *key_pair)
{
  Log(kDot2LogLevel_Event, "Make cocoon private key - i: 0x%04X, j: 0x%04X\n", i, j);
  int ret = -kDot2Result_OSSL_MakeCocoonPrivateKey;

  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  BN_CTX *bn_ctx = NULL;
  const BIGNUM *bn_order = EC_GROUP_get0_order(ecg);
  const EC_POINT *ecp_G = EC_GROUP_get0_generator(ecg);
  BIGNUM *bn_f1_k_x = NULL, *bn_f1_int_k_x = NULL, *bn_seed_priv = NULL, *bn_priv_key = NULL, *bn_tmp = NULL;
  EC_POINT *ecp_seed_pub = NULL, *ecp_tmp = NULL, *ecp_pub_key = NULL;

  /*
   * f1int(k, x) 방정식을 계산한다. (x = i, j)
   */
  uint8_t x[DOT2_AES_128_LEN], f1_int_k_x[DOT2_AES_128_LEN * 3];
  dot2_ossl_derive_signing_x(i, j, x);
  if (((bn_ctx = BN_CTX_new()) == NULL) ||
      (dot2_ossl_f_int_k_x(exp_key->octs, x, f1_int_k_x) == false) ||
      ((bn_f1_int_k_x = BN_bin2bn(f1_int_k_x, sizeof(f1_int_k_x), NULL)) == NULL) ||
      ((bn_f1_k_x = BN_new()) == NULL) ||
      (BN_mod(bn_f1_k_x, (const BIGNUM *)bn_f1_int_k_x, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) {
    Err("Fail to make cocoon private key - f1(k,x) calculation failed\n");
    goto out;
  }

  /*
   * Cocoon 개인키를 계산한다.
   *  - 계산식: private key = (seed_priv + f(k,x)) % l(=order n)
   *  - bn_priv_key = bn_tmp % bn_order
   *    - bn_tmp = bn_seed_priv + bn_f1_k_x
   */
  if (((bn_tmp = BN_new()) == NULL) ||
      ((bn_priv_key = BN_new()) == NULL) ||
      ((bn_seed_priv = BN_bin2bn(seed_priv->octs, DOT2_EC_256_KEY_LEN, NULL)) == NULL) ||
      (BN_add(bn_tmp, bn_seed_priv, bn_f1_k_x) == DOT2_OSSL_FAIL) ||
      (BN_mod(bn_priv_key, bn_tmp, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) {
    Err("Fail to make cocoon private key - private key calculation failed\n");
    goto out;
  }

  /*
   * Cocoon 공개키를 계산한다.
   *  - 계산식: public key = (seed_priv * G) + (f1(k,x) * G)
   *  - ec_pub_key = ec_seed_pub + ec_tmp1
   *    - ec_seed_pub = bn_seed_priv * ecp_generator
   *    - ec_tmp1 = bn_f1_k_x * ecp_generator
   *  - 본 결과는 public key = private key * G 계산의 결과와 동일하다.
   */
  if (((ecp_seed_pub = EC_POINT_new(ecg)) == NULL) ||
      ((ecp_tmp = EC_POINT_new(ecg)) == NULL) ||
      ((ecp_pub_key = EC_POINT_new(ecg)) == NULL) ||
      (EC_POINT_mul(ecg, ecp_seed_pub, NULL, ecp_G, bn_seed_priv, bn_ctx) == DOT2_OSSL_FAIL) ||
      (EC_POINT_mul(ecg, ecp_tmp, NULL, ecp_G, bn_f1_k_x, bn_ctx) == DOT2_OSSL_FAIL) ||
      (EC_POINT_add(ecg, ecp_pub_key, ecp_seed_pub, ecp_tmp, bn_ctx) == DOT2_OSSL_FAIL)) {
    Err("Fail to expand key pair - public key calculation failed\n");
    goto out;
  }

  /*
   * BIGNUM 형식의 Cocoon 개인키로 부터 개인키바이트열을 얻는다.
   */
  if (dot2_ossl_GetPrivKeyOctsFromBIGNUM(bn_priv_key, &(key_pair->priv_key)) == false) {
    Err("Fail to make cocoon private key - dot2_ossl_GetPrivKeyOctsFromBIGNUM() failed\n");
    goto out;
  }

  /*
   * EC_POINT 형식의 Cocoon 공개키로부터 공개키바이트열을 얻는다.
   */
  if (dot2_ossl_GetUncompressedPointOctsFromECPOINT(ecp_pub_key, &(key_pair->pub_key)) < 0) {
    Err("Fail to make cocoon private key - dot2_ossl_GetUncompressedPointOctsFromECPOINT() failed\n");
    goto out;
  }

  ret = kDot2Result_Success;

out:
  if (bn_f1_k_x) { BN_free(bn_f1_k_x); }
  if (bn_f1_int_k_x) { BN_free(bn_f1_int_k_x); }
  if (bn_seed_priv) { BN_free(bn_seed_priv); }
  if (bn_priv_key) { BN_free(bn_priv_key); }
  if (bn_tmp) { BN_free(bn_tmp); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  if (ecp_seed_pub) { EC_POINT_free(ecp_seed_pub); }
  if (ecp_tmp) { EC_POINT_free(ecp_tmp); }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  return ret;
}


/**
 * @brief 암호화용 개인키/공개키를 재구성하는데 사용되는 Cocoon 키쌍을 만든다.
 * @param[in] i 인증서 i 값. 예: 인증서 파일명 중 앞 숫자 (8E_0.cert 중 8E)
 * @param[in] j 인증서 j 값. i 주 내에서의 인증서 순서 (0~19). 예: 인증서 파일명 중 뒤 숫자 (8E_0.cert 중 0)
 * @param[in] exp_key 확장함수 키
 * @param[in] seed_priv 시드개인키 (caterpillar 개인키)
 * @param[out] key_pair Cocoon 키쌍이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 암호화용 Coccon 개인키/공개키는 다음과 같이 계산된다. \n
 *  - 재구성용 개인키 bn = a + f2(i,j) \n
 *  - 재구성용 공개키 Bn = A + f2(i,j) * G \n
 *      a : seed_priv: 인증서암호화용 시드개인키
 *      A : seed_pub = seed_priv * G
 *      G : ECC curve generator
 */
int INTERNAL dot2_ossl_MakeEncryptionCocoonKeyPair(
  uint32_t i,
  uint32_t j,
  const struct Dot2AESKey *exp_key,
  const struct Dot2ECPrivateKey *seed_priv,
  struct Dot2ECKeyPairOcts *key_pair)
{
  Log(kDot2LogLevel_Event, "Make cocoon private key - i: 0x%04X, j: 0x%04X\n", i, j);
  int ret = -kDot2Result_OSSL_MakeCocoonPrivateKey;

  EC_GROUP *ecg = g_dot2_mib.sec_executer.ossl.ecg;
  BN_CTX *bn_ctx = NULL;
  const BIGNUM *bn_order = EC_GROUP_get0_order(ecg);
  const EC_POINT *ecp_G = EC_GROUP_get0_generator(ecg);
  BIGNUM *bn_f1_k_x = NULL, *bn_f1_int_k_x = NULL, *bn_seed_priv = NULL, *bn_priv_key = NULL, *bn_tmp = NULL;
  EC_POINT *ecp_seed_pub = NULL, *ecp_tmp = NULL, *ecp_pub_key = NULL;

  /*
   * f2int(k, x) 방정식을 계산한다. (x = i, j)
   */
  uint8_t x[DOT2_AES_128_LEN], f1_int_k_x[DOT2_AES_128_LEN * 3];
  dot2_ossl_derive_encryption_x(i, j, x);
  if (((bn_ctx = BN_CTX_new()) == NULL) ||
      (dot2_ossl_f_int_k_x(exp_key->octs, x, f1_int_k_x) == false) ||
      ((bn_f1_int_k_x = BN_bin2bn(f1_int_k_x, sizeof(f1_int_k_x), NULL)) == NULL) ||
      ((bn_f1_k_x = BN_new()) == NULL) ||
      (BN_mod(bn_f1_k_x, (const BIGNUM *)bn_f1_int_k_x, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) {
    Err("Fail to make cocoon private key - f1(k,x) calculation failed\n");
    goto out;
  }

  /*
   * Cocoon 개인키를 계산한다.
   *  - 계산식: private key = (seed_priv + f(k,x)) % l(=order n)
   *  - bn_priv_key = bn_tmp % bn_order
   *    - bn_tmp = bn_seed_priv + bn_f1_k_x
   */
  if (((bn_tmp = BN_new()) == NULL) ||
      ((bn_priv_key = BN_new()) == NULL) ||
      ((bn_seed_priv = BN_bin2bn(seed_priv->octs, DOT2_EC_256_KEY_LEN, NULL)) == NULL) ||
      (BN_add(bn_tmp, bn_seed_priv, bn_f1_k_x) == DOT2_OSSL_FAIL) ||
      (BN_mod(bn_priv_key, bn_tmp, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) {
    Err("Fail to make cocoon private key - private key calculation failed\n");
    goto out;
  }

  /*
   * Cocoon 공개키를 계산한다.
   *  - 계산식: public key = (seed_priv * G) + (f1(k,x) * G)
   *  - ec_pub_key = ec_seed_pub + ec_tmp1
   *    - ec_seed_pub = bn_seed_priv * ecp_generator
   *    - ec_tmp1 = bn_f1_k_x * ecp_generator
   *  - 본 결과는 public key = private key * G 계산의 결과와 동일하다.
   */
  if (((ecp_seed_pub = EC_POINT_new(ecg)) == NULL) ||
      ((ecp_tmp = EC_POINT_new(ecg)) == NULL) ||
      ((ecp_pub_key = EC_POINT_new(ecg)) == NULL) ||
      (EC_POINT_mul(ecg, ecp_seed_pub, NULL, ecp_G, bn_seed_priv, bn_ctx) == DOT2_OSSL_FAIL) ||
      (EC_POINT_mul(ecg, ecp_tmp, NULL, ecp_G, bn_f1_k_x, bn_ctx) == DOT2_OSSL_FAIL) ||
      (EC_POINT_add(ecg, ecp_pub_key, ecp_seed_pub, ecp_tmp, bn_ctx) == DOT2_OSSL_FAIL)) {
    Err("Fail to expand key pair - public key calculation failed\n");
    goto out;
  }

  /*
   * BIGNUM 형식의 Cocoon 개인키로 부터 개인키바이트열을 얻는다.
   */
  if (dot2_ossl_GetPrivKeyOctsFromBIGNUM(bn_priv_key, &(key_pair->priv_key)) == false) {
    Err("Fail to make cocoon private key - dot2_ossl_GetPrivKeyOctsFromBIGNUM() failed\n");
    goto out;
  }

  /*
   * EC_POINT 형식의 Cocoon 공개키로부터 공개키바이트열을 얻는다.
   */
  if (dot2_ossl_GetUncompressedPointOctsFromECPOINT(ecp_pub_key, &(key_pair->pub_key)) < 0) {
    Err("Fail to make cocoon private key - dot2_ossl_GetUncompressedPointOctsFromECPOINT() failed\n");
    goto out;
  }

  ret = kDot2Result_Success;

out:
  if (bn_f1_k_x) { BN_free(bn_f1_k_x); }
  if (bn_f1_int_k_x) { BN_free(bn_f1_int_k_x); }
  if (bn_seed_priv) { BN_free(bn_seed_priv); }
  if (bn_priv_key) { BN_free(bn_priv_key); }
  if (bn_tmp) { BN_free(bn_tmp); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  if (ecp_seed_pub) { EC_POINT_free(ecp_seed_pub); }
  if (ecp_tmp) { EC_POINT_free(ecp_tmp); }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  return ret;
}


/**
 * @brief Butterfly 키 확장을 통해 서명용 개인키를 재구성한다.
 * @param[in] i 인증서 i 값. 예: 인증서 파일명 중 앞 숫자 (8E_0.cert 중 8E)
 * @param[in] j 인증서 j 값. i 주 내에서의 인증서 순서 (0~19). 예: 인증서 파일명 중 뒤 숫자 (8E_0.cert 중 0)
 * @param[in] exp_key 확장함수 키
 * @param[in] seed_priv 시드개인키 (caterpillar 개인키)
 * @param[in] recon_priv 개인키 재구성값
 * @param[in] recon_pub 공개키 재구성값
 * @param[in] cert 인증서바이트열
 * @param[in] issuer_h 상위인증서에 대한 해시
 * @param[in] issuer_pub_key 상위인증서 공개키
 * @param[out] priv_key 재구성된 개인키바이트열이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * KISA v1.1 규격에 따라,
 *  - i = 0 시점은 2015년 1월 6일(화요일) 오전 2:00 이다.
 *  - 미국 CAMP의 기준시간 2015년 1월 6일(화요일) 오전 4:00(동부표준시)보다 16시간 빠른시간이며,
 *    1609.2 시각(2004년 1월 1일 00:00:00) 이후로 TAI 347,562,003초를 의미한다.
 *  - i=0에 대응하는 시각 값은 V2X 보안인증체계를 제공하는 국가마다 상이할 수 있으므로 해당 값은 필요시 수정 가능하도록 개발되어야 한다.
 */
int INTERNAL dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(
  uint32_t i,
  uint32_t j,
  const struct Dot2AESKey *exp_key,
  const struct Dot2ECPrivateKey *seed_priv,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2ECPublicKey *recon_pub,
  const struct Dot2Cert *cert,
  const struct Dot2SHA256 *issuer_h,
  const struct Dot2ECPublicKey *issuer_pub_key,
  struct Dot2ECPrivateKey *priv_key)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert butterfly private key 1\n");

  EC_KEY *eck_priv_key = NULL, *eck_pub_key = NULL;

  /*
   * Cocoon 키쌍을 생성한다.
   */
  struct Dot2ECKeyPairOcts cocoon_key_pair;
  int ret = dot2_ossl_MakeSigningCocoonKeyPair(i, j, exp_key, seed_priv, &cocoon_key_pair);
  if (ret < 0) {
    Err("Fail to reconstruct implicit cert butterfly prviate key 1 - dot2_ossl_MakeSigningCocoonKeyPair() failed\n");
    return ret;
  }

  /*
   * Cocoon 키를 이용하여 개인키를 재구성한다.
   */
  eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(&(cocoon_key_pair.priv_key),
                                                               recon_priv,
                                                               cert,
                                                               issuer_h,
                                                               priv_key,
                                                               &ret);
  if (eck_priv_key == NULL) {
    Err("Fail to reconstruct implicit cert butterfly prviate key 1 - dot2_ossl_ReconstructImplicitCertPrivateKey_1() failed\n");
    return ret;
  }

  /*
   * Cocoon 키를 이용하여 공개키를 재구성한다.
   */
  struct Dot2ECPublicKey pub_key;
  eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(recon_pub, cert, issuer_h, issuer_pub_key, &pub_key, &ret);
  if (eck_pub_key == NULL) {
    Err("Fail to reconstruct implicit cert butterfly prviate key 1 - dot2_ossl_ReconstructImplicitCertPublicKey_1() failed\n");
    goto out;
  }

  /*
   * 재구성된 개인키와 공개키의 쌍이 맞는지 확인한다.
   */
  if (dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key) == false) {
    Err("Fail to reconstruct implicit cert butterfly prviate key 1 - dot2_ossl_CheckECKEYKeyPair() failed\n");
    ret = -kDot2Result_OSSL_InvalidReconstructedKeyPair;
    goto out;
  }

  ret = kDot2Result_Success;

out:
  if (eck_priv_key) { EC_KEY_free(eck_priv_key); }
  if (eck_pub_key) { EC_KEY_free(eck_pub_key); }
  return ret;
}
