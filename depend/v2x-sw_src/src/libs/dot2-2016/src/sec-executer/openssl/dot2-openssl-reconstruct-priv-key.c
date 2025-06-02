/** 
 * @file
 * @brief openssl을 이용하여 Implicit 인증서 기반 개인키를 재구성하는 기능을 구현한 파일
 * @date 2020-03-05
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
 * @brief BIGNUM 형식의 임시개인키, 개인키재구성값, 해시값을 이용하여 개인키를 재구성한다.
 * @param[in] bn_init_priv_key 인증서 요청시 생성한 임시 개인키
 * @param[in] bn_recon_priv 개인키 재구성값
 * @param[in] bn_input_h 재구성 연산에 입력될 해시값 = H(CertU)
 * @return 재구성된 개인키 BIGNUM 포인터
 * @retval NULL: 실패
 *
 * 재구성 연산은 다음과 같다. \n
   * 	- bn_hash * bn_init_priv_key + bn_recon_priv
 */
BIGNUM INTERNAL *dot2_ossl_ReconstructBIGNUMPrivateKey(
  const BIGNUM *bn_init_priv_key,
  const BIGNUM *bn_recon_priv,
  const BIGNUM *bn_input_h)
{
  BN_CTX *bn_ctx = NULL;
  EC_GROUP *ec_group = g_dot2_mib.sec_executer.ossl.ecg;
  const BIGNUM *bn_order = EC_GROUP_get0_order(ec_group);
  BIGNUM *bn_priv_key = NULL, *bn_tmp0 = NULL, *bn_tmp1 = NULL;

  /*
   * 계산을 위해 필요한 임시 변수를 할당한다.
   */
  if (((bn_ctx = BN_CTX_new()) != NULL) &&
      ((bn_priv_key = BN_new()) != NULL)) {
    if (((bn_tmp0 = BN_new()) == NULL) ||
        ((bn_tmp1 = BN_new()) == NULL) ||
        (BN_mul(bn_tmp0, bn_input_h, bn_init_priv_key, bn_ctx) == DOT2_OSSL_FAIL) ||
        (BN_add(bn_tmp1, (const BIGNUM *)bn_tmp0, bn_recon_priv) == DOT2_OSSL_FAIL) ||
        (BN_mod(bn_priv_key, (const BIGNUM *)bn_tmp1, bn_order, bn_ctx) == DOT2_OSSL_FAIL)) {
      BN_free(bn_priv_key);
      bn_priv_key = NULL;
    }
  }

  if (bn_tmp0) { BN_free(bn_tmp0); }
  if (bn_tmp1) { BN_free(bn_tmp1); }
  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  return bn_priv_key;
}


/**
 * @brief 바이트열 형식의 개인키 재구성 파라미터들로부터 BIGNUM 형식의 개인키 재구성 파라미터들을 생성한다.
 * @param[in] init_priv_key 인증서 발급요청 개인키 바이트열
 * @param[in] recon_priv 개인키재구성값 바이트열
 * @param[in] h_input 해시입력 바이트열
 * @param[out] bn_init_priv_key BIGNUM 형식 인증서 발급요청 개인키가 저장될 구조체 포인터 (사용 후 BN_free() 되어야 한다)
 * @param[out] bn_recon_priv BIGNUM 형식 개인키재구성값이 저장될 구조체 포인터 (사용 후 BN_free() 되어야 한다)
 * @param[out] bn_input_h BIGNUM 형식 해시입력이 저장될 구조체 포인터 (사용 후 BN_free() 되어야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ossl_MakeBIGNUMPrivKeyReconstructParamsFromOcts(
  const struct Dot2ECPrivateKey *init_priv_key,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2SHA256 *h_input,
  BIGNUM **bn_init_priv_key,
  BIGNUM **bn_recon_priv,
  BIGNUM **bn_input_h)
{
  BIGNUM *bn_init_priv_key_ = NULL, *bn_recon_priv_ = NULL, *bn_input_h_ = NULL;
  if (((bn_init_priv_key_ = BN_bin2bn(init_priv_key->octs, DOT2_EC_256_KEY_LEN, NULL)) != NULL) &&
      ((bn_recon_priv_ = BN_bin2bn(recon_priv->octs, DOT2_EC_256_KEY_LEN, NULL)) != NULL) &&
      ((bn_input_h_ = BN_bin2bn(h_input->octs, sizeof(h_input->octs), NULL)) != NULL)) {
    *bn_init_priv_key = bn_init_priv_key_;
    *bn_recon_priv = bn_recon_priv_;
    *bn_input_h = bn_input_h_;
    return kDot2Result_Success;
  }

  if (bn_init_priv_key_) { BN_free(bn_init_priv_key_); }
  if (bn_recon_priv_) { BN_free(bn_recon_priv_); }
  if (bn_input_h_) { BN_free(bn_input_h_); }
  return -kDot2Result_OSSL_MakeBIGNUMPrivKeyReconstructParamsFromOcts;
}


/**
 * @brief Implicit 인증서 개인키를 재구성한다. (바이트열 형식 개인키와 EC_KEY 형식 개인키가 반환된다)
 * @param[in] init_priv_key 초기 개인키 (예: dwnl_sgn.priv 파일)
 * @param[in] recon_priv 개인키 재구성값 (예: *.s 파일)
 * @param[in] cert 인증서 바이트열
 * @param[in] cert_size 인증서 바이트열의 길이
 * @param[in] issuer_h 상위인증서에 대한 해시
 * @param[out] priv_key 재구성된 개인키바이트열이 저장될 구조체 포인터
 * @param[out] err 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 개인키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 개인키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 개인키 = H(CertU) * init_priv_key + recon_priv \n
 *  - CertU = H(ToBeSignedCertificate) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPrivateKey_1(
  const struct Dot2ECPrivateKey *init_priv_key,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2Cert *cert,
  const struct Dot2SHA256 *issuer_h,
  struct Dot2ECPrivateKey *priv_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert private key\n");

  /*
   * 인증서 내 ToBeSignedCertifcate 필드를 구한다.
   */
  const uint8_t *tbs_cert = DOT2_GET_ISSUER_SIGNED_CERT_TBS(cert->octs);
  size_t tbs_cert_size = DOT2_GET_ISSUER_SIGNED_IMPLICIT_CERT_TBS_SIZE(cert->size);

  /*
   * H(ToBeSignedCertificate)를 계산한다.
   */
  struct Dot2SHA256 tbs_cert_h;
  SHA256(tbs_cert, tbs_cert_size, tbs_cert_h.octs);

  /*
   * 개인키를 재구성한다.
   */
  return dot2_ossl_ReconstructImplicitCertPrivateKey_2(init_priv_key, recon_priv, &tbs_cert_h, issuer_h, priv_key, err);
}


/**
 * @brief Implicit 인증서 개인키를 재구성한다. (바이트열 형식 개인키와 EC_KEY 형식 개인키가 반환된다)
 * @param[in] init_priv_key 인증서 발급요청 시 임시로 생성한 초기개인키 (예: dwnl_sgn.priv 파일)
 * @param[in] recon_priv 개인키 재구성값 (예: *.s 파일)
 * @param[in] tbs_cert_h 인증서내 ToBeSignedCertificate 영역에 대한 해시
 * @param[in] issuer_h 상위인증서에 대한 해시
 * @param[out] priv_key 재구성된 개인키바이트열이 저장될 구조체 포인터
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 개인키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 개인키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 개인키 = H(CertU) * init_priv_key + recon_priv \n
 *  - CertU = H(cert_tbs) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPrivateKey_2(
  const struct Dot2ECPrivateKey *init_priv_key,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2SHA256 *tbs_cert_h,
  const struct Dot2SHA256 *issuer_h,
  struct Dot2ECPrivateKey *priv_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert private key\n");

  /*
   * 키 재구성 연산에 입력될 해시값(H(CertU))을 계산한다.
   */
  struct Dot2SHA256 h_input;
  dot2_ossl_CalculateKeyReconstructionHashInput_3(tbs_cert_h, issuer_h, &h_input);

  /*
   * 개인키를 재구성한다.
   */
  return dot2_ossl_ReconstructImplicitCertPrivateKey_3(init_priv_key, recon_priv, &h_input, priv_key, err);
}


/**
 * @brief Implicit 인증서 개인키를 재구성한다. (바이트열 형식 개인키와 EC_KEY 형식 개인키가 반환된다)
 * @param[in] init_priv_key 인증서 발급요청 시 임시로 생성한 개인키(kU) (예: dwnl_sgn.priv 파일)
 * @param[in] recon_priv 개인키 재구성값(r). (예: *.s 파일)
 * @param[in] h_input 개인키 재구성 연산에 사용되는 해시 입력
 * @param[in] issuer_h 상위인증서에 대한 해시
 * @param[out] priv_key 재구성된 개인키바이트열이 저장될 구조체 포인터
 * @param[out] 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 개인키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 개인키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 개인키 = H(CertU) * init_priv_key + recon_priv \n
 *  - CertU = H(cert_tbs) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPrivateKey_3(
  const struct Dot2ECPrivateKey *init_priv_key,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2SHA256 *h_input,
  struct Dot2ECPrivateKey *priv_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert private key\n");

  BIGNUM *bn_init_priv_key = NULL, *bn_recon_priv = NULL, *bn_input_h = NULL, *bn_priv_key = NULL;
  EC_KEY *eck_priv_key = NULL;

  /*
   * 재구성 연산을 위해 바이트열 형식의 개인키재구성파라미터들을 BIGNUM 형식으로 변환한다.
   */
  int ret = dot2_ossl_MakeBIGNUMPrivKeyReconstructParamsFromOcts(init_priv_key,
                                                                 recon_priv,
                                                                 h_input,
                                                                 &bn_init_priv_key,
                                                                 &bn_recon_priv,
                                                                 &bn_input_h);
  if (ret < 0) {
    goto err;
  }

  /*
   * 개인키를 재구성하고, 재구성된 개인키를 EC_KEY 형식 및 바이트열 형식 개인키 정보에 저장한다.
   */
  ret = -kDot2Result_OSSL_ReconstructBIGNUMPrivateKey;
  bn_priv_key = dot2_ossl_ReconstructBIGNUMPrivateKey(bn_init_priv_key, bn_recon_priv, bn_input_h);
  if (bn_priv_key) {
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromBIGNUMPrivKey(bn_priv_key, &ret);
    if (eck_priv_key) {
      ret = dot2_ossl_GetPrivKeyOctsFromECKEY(eck_priv_key, priv_key);
      if (ret < 0) {
        EC_KEY_free(eck_priv_key);
        eck_priv_key = NULL;
      }
    }
  }

err:
  if (bn_init_priv_key) { BN_free(bn_init_priv_key); }
  if (bn_recon_priv) { BN_free(bn_recon_priv); }
  if (bn_input_h) { BN_free(bn_input_h); }
  if (bn_priv_key) { BN_free(bn_priv_key); }
  *err = ret;
  return eck_priv_key;
}
