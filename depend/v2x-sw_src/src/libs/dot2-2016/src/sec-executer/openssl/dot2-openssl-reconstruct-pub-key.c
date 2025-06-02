/** 
  * @file 
  * @brief openssl을 이용하여 Implicit 인증서 기반 공개키를 재구성하는 기능을 구현한 파일
  * @date 2022-07-31 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <assert.h>

// 라이브러리 의존 헤더 파일
#include "openssl/bn.h"
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-openssl-inline.h"


/**
 * @brief EC_POINT 형식의 공개키재구성값, 상위인증서 공개키와 BIGNUM 형식의 해시값을 이용하여 공개키를 재구성한다.
 * @param[in] ecp_recon_pub 공개키 재구성값
 * @param[in] ecp_issuer_pub_key 상위인증서 공개키
 * @param[in] bn_h 재구성 연산에 입력될 해시값 = H(CertU)
 * @return EC_POINT 형식의 공개키
 * @retval NULL: 실패
 *
 * 공개키 재구성 연산식은 다음과 같다. \n
 *  - (bn_h * ecp_recon_pub) + ecp_issuer_pub_key
 */
static EC_POINT *dot2_ossl_ReconstructECPOINTPublicKey(
  const EC_POINT *ecp_recon_pub,
  const EC_POINT *ecp_issuer_pub_key,
  const BIGNUM *bn_h)
{
  EC_POINT *ecp_tmp = NULL, *ecp_pub_key = NULL;
  EC_GROUP *ec_group = g_dot2_mib.sec_executer.ossl.ecg;
  BN_CTX *bn_ctx = NULL;

  if (((bn_ctx = BN_CTX_new()) != NULL) &&
      (ecp_pub_key = EC_POINT_new(ec_group)) != NULL) {
    if (((ecp_tmp = EC_POINT_new(ec_group)) == NULL) ||
        (EC_POINT_mul(ec_group, ecp_tmp, 0, ecp_recon_pub, bn_h, bn_ctx) == DOT2_OSSL_FAIL) ||
        (EC_POINT_add(ec_group, ecp_pub_key, ecp_tmp, ecp_issuer_pub_key, bn_ctx) == DOT2_OSSL_FAIL)) {
      EC_POINT_free(ecp_pub_key);
      ecp_pub_key = NULL;
    }
  }

  if (bn_ctx) { BN_CTX_free(bn_ctx); }
  if (ecp_tmp) { EC_POINT_free(ecp_tmp); }
  return ecp_pub_key;
}


/**
 * @brief Implicit 인증서 공개키를 재구성한다.
 * @param[in] recon_pub 공개키 재구성값
 * @param[in] cert 인증서 바이트열
 * @param[in] issuer_h 상위인증서 해시
 * @param[in] issuer_pub_key 상위인증서 공개키
 * @param[out] pub_key 재구성된 공개키자 저장될 구조체 포인터
 * @param[out] err 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 공개키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 공개키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 공개키 = H(CertU) * recon_pub + issuer_pub_key \n
 *  - CertU = H(tbs_cert_sign) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_1(
  const struct Dot2ECPublicKey *recon_pub,
  const struct Dot2Cert *cert,
  const struct Dot2SHA256 *issuer_h,
  const struct Dot2ECPublicKey *issuer_pub_key,
  struct Dot2ECPublicKey *pub_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert public key 1\n");

  /*
   * 인증서 내 ToBeSignedCertificate 필드를 구한다.
   */
  const uint8_t *tbs_cert = DOT2_GET_ISSUER_SIGNED_CERT_TBS(cert->octs);
  size_t tbs_cert_size = DOT2_GET_ISSUER_SIGNED_IMPLICIT_CERT_TBS_SIZE(cert->size);

  /*
   * H(ToBeSignedCertificate)를 계산한다.
   */
  struct Dot2SHA256 tbs_cert_h;
  SHA256(tbs_cert, tbs_cert_size, tbs_cert_h.octs);

  /*
   * 공개키를 재구성한다.
   */
  return dot2_ossl_ReconstructImplicitCertPublicKey_2(recon_pub, &tbs_cert_h, issuer_h, issuer_pub_key, pub_key, err);
}


/**
 * @brief Implicit 인증서 공개키를 재구성한다.
 * @param[in] recon_pub 공개키 재구성값
 * @param[in] tbs_cert_h 인증서내 ToBeSignedCertificate 영역에 대한 해시
 * @param[in] issuer_h 상위인증서 해시
 * @param[in] issuer_pub_key 상위인증서 공개키
 * @param[out] pub_key 재구성된 공개키자 저장될 구조체 포인터
 * @param[out] err 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 공개키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 공개키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 공개키 = H(CertU) * recon_pub + issuer_pub_key \n
 *  - CertU = H(tbs_cert_sign) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_2(
  const struct Dot2ECPublicKey *recon_pub,
  const struct Dot2SHA256 *tbs_cert_h,
  const struct Dot2SHA256 *issuer_h,
  const struct Dot2ECPublicKey *issuer_pub_key,
  struct Dot2ECPublicKey *pub_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert public key 2\n");

  /*
   * 키 재구성 연산에 입력될 해시값(H(CertU))을 계산한다.
   */
  struct Dot2SHA256 h_input;
  dot2_ossl_CalculateKeyReconstructionHashInput_3(tbs_cert_h, issuer_h, &h_input);

  /*
   * 공개키를 재구성한다.
   */
  return dot2_ossl_ReconstructImplicitCertPublicKey_3(recon_pub, &h_input, issuer_pub_key, pub_key, err);
}


/**
 * @brief Implicit 인증서 공개키를 재구성한다.
 * @param[in] recon_pub 공개키 재구성값
 * @param[in] h_input 공개키 재구성 연산에 사용되는 해시 입력
 * @param[in] issuer_pub_key 상위인증서 공개키
 * @param[out] pub_key 재구성된 공개키자 저장될 구조체 포인터
 * @param[out] err 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 공개키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 공개키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 공개키 = H(CertU) * recon_pub + issuer_pub_key \n
 *  - CertU = H(tbs_cert) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_3(
  const struct Dot2ECPublicKey *recon_pub,
  const struct Dot2SHA256 *h_input,
  const struct Dot2ECPublicKey *issuer_pub_key,
  struct Dot2ECPublicKey *pub_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert public key 3\n");

  EC_POINT *ecp_issuer_pub_key = NULL;
  EC_KEY *eck_pub_key = NULL;

  /*
   * 바이트열 형식의 상위인증서 공개키를 EC_POINT 형식으로 변환한다.
   */
  ecp_issuer_pub_key = dot2_ossl_MakeECPOINTfromPointOcts(issuer_pub_key, err);
  if (ecp_issuer_pub_key == NULL) {
    Err("Fail to reconstruct implicit cert public key - dot2_ossl_MakeECPOINTfromPointOcts(issuer_pub_key) failed\n");
    return NULL;
  }

  /*
   * 공개키를 재구성한다.
   */
  eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_4(recon_pub, h_input, ecp_issuer_pub_key, err);
  if (eck_pub_key == NULL) {
    goto out;
  }

  /*
   * 재구성된 공개키를 바이트열형식으로 변환한다.
   */
  const EC_POINT *ecp_pub_key = EC_KEY_get0_public_key(eck_pub_key);
  assert(ecp_pub_key);
  *err = dot2_ossl_GetUncompressedPointOctsFromECPOINT(ecp_pub_key, pub_key);
  if (*err < 0) {
    Err("Fail to reconstruct implicit cert public key - dot2_ossl_GetUncompressedPointOctsFromECPOINT(ecp_pub_key) failed\n");
    EC_KEY_free(eck_pub_key);
    eck_pub_key = NULL;
  }

out:
  EC_POINT_free(ecp_issuer_pub_key);
  return eck_pub_key;
}



/**
 * @brief Implicit 인증서 공개키를 재구성한다.
 * @param[in] recon_pub 공개키 재구성값
 * @param[in] h_input 공개키 재구성 연산에 사용되는 해시 입력
 * @param[in] ecp_issuer_pub_key 상위인증서 공개키
 * @param[out] err 실패 시 결과코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 개인키가 포함된 EC_KEY 정보 (사용 후 EC_KEY_free() 되어야 한다)
 * @retval NULL: 실패
 *
 * 공개키는 다음과 같은 계산식에 의해 재구성된다. \n
 *  - 공개키 = H(CertU) * recon_pub + issuer_pub_key \n
 *  - CertU = H(tbs_cert) || H(issuer_cert)
 */
EC_KEY INTERNAL * dot2_ossl_ReconstructImplicitCertPublicKey_4(
  const struct Dot2ECPublicKey *recon_pub,
  const struct Dot2SHA256 *h_input,
  const EC_POINT *ecp_issuer_pub_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct implicit cert public key 4\n");

  int ret;
  BIGNUM *bn_h_input = NULL;
  EC_POINT *ecp_pub_key = NULL;
  EC_POINT *ecp_recon_pub = NULL;
  EC_KEY *eck_pub_key = NULL;

  /*
   * 바이트열 형식의 공개키재구성값을 EC_POINT 형식으로 변환한다.
   */
  ecp_recon_pub = dot2_ossl_MakeECPOINTfromPointOcts(recon_pub, &ret);
  if (ecp_recon_pub == NULL) {
    Err("Fail to reconstruct implicit cert public key - dot2_ossl_MakeECPOINTfromPointOcts(recon_pub) failed\n");
    goto out;
  }

  /*
   * 바이트열 형식의 해시입력을 BIGNUM 형식으로 변환한다.
   */
  bn_h_input = BN_bin2bn(h_input->octs, sizeof(h_input->octs), NULL);
  if (bn_h_input == NULL) {
    Err("Fail to reconstruct implicit cert public key - BN_bin2bn(h_input) failed\n");
    ret = -kDot2Result_OSSL_MakeBIGNUMHashFromOcts;
    goto out;
  }

  /*
   * 공개키를 재구성한다.
   */
  ecp_pub_key = dot2_ossl_ReconstructECPOINTPublicKey(ecp_recon_pub, ecp_issuer_pub_key, bn_h_input);
  if (ecp_pub_key == NULL) {
    Err("Fail to reconstruct implicit cert public key - dot2_ossl_ReconstructECPOINTPublicKey() failed\n");
    ret = -kDot2Result_OSSL_ReconstructECPOINTPublicKey;
    goto out;
  }

  /*
   * 재구성된 공개키가 포함된 EC_KEY 정보를 생성한다.
   */
  eck_pub_key = dot2_ossl_MakeECKEYPubKeyFromECPOINTPubKey(ecp_pub_key);
  if (eck_pub_key == NULL) {
    Err("Fail to reconstruct implicit cert public key - dot2_ossl_MakeECKEYPubKeyFromECPOINTPubKey(ecp_pub_key) failed\n");
    ret = -kDot2Result_OSSL_ReconstructECPOINTPublicKey;
  } else {
    Log(kDot2LogLevel_Event, "Success to reconstruct implicit cert public key\n");
    ret = kDot2Result_Success;
  }

out:
  *err = ret;
  if (bn_h_input) { BN_free(bn_h_input); }
  if (ecp_pub_key) { EC_POINT_free(ecp_pub_key); }
  if (ecp_recon_pub) { EC_POINT_free(ecp_recon_pub); }
  return eck_pub_key;
}


#if defined(_SIGN_VERIFY_OPENSSL_)
/**
 * @brief 서명자(인증서) 공개키를 재구성한다.
 * @param[in] h_input 서명자(인증서) 공개키 재구성 입력 해시 값 ( = H(tbs_cert_sign) || H(issuer_cert))
 * @param[in] signer_recon_pub 서명자(인증서) 공개키 재구성 값
 * @param[in] eck_issuer_pub_key 상위인증서(pca/aca) 공개키
 * @param[out] pub_key 재구성된 공개키가 저장될 구조체 포인터(단위테스트 시에만 사용된다)
 * @param[out] err 실패 시 에러코드(-Dot2ResultCode)가 저장될 변수 포인터
 * @return 재구성된 공개키 (EC_KEY 형식)
 * @retval NULL: 실패
 */
static EC_KEY * dot2_ossl_ReconstructSignerPublicKey(
  struct Dot2SHA256 *h_input,
  struct Dot2ECPublicKey *signer_recon_pub,
  const EC_KEY *eck_issuer_pub_key,
  struct Dot2ECPublicKey *pub_key,
  int *err)
{
  Log(kDot2LogLevel_Event, "Reconstruct signer public key\n");

  /*
   * 공개키를 재구성한다.
   */
  (void)pub_key;
  const EC_POINT *ecp_issuer_pub_key = EC_KEY_get0_public_key(eck_issuer_pub_key);
  EC_KEY *eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_4(signer_recon_pub, h_input, ecp_issuer_pub_key, err);
  if (eck_pub_key == NULL) {
    Err("Fail to reconstruct signer public key - dot2_ossl_ReconstructImplicitCertPublicKey_4() failed\n");
    return NULL;
  }

#if defined(_UNIT_TEST_)
  /*
   * 재구성된 공개키를 바이트열 형식으로 변환하여 추가 저장한다.
   * (Openssl 기반 서명검증 지원 시) 서명검증할 때에는 바이트열 형식 공개키가 아닌 EC_KEY 형식 공개키가 사용되므로,
   *                              바이트열 형식 공개키를 저장할 필요 없다.
   * 단위테스트 결과 비교를 위해서만 바이트열 형식 공개키를 저장한다.
   */
  int ret = dot2_ossl_GetUncompressedPubKeyOctsFromECKEY(eck_pub_key, pub_key);
  if (ret < 0) {
    Err("Fail to reconstruct signer public key - dot2_ossl_GetUncompressedPubKeyOctsFromECKEY() failed\n");
    EC_KEY_free(eck_pub_key);
    *err = ret;
    return NULL;
  }
#endif

 return eck_pub_key;
}


/**
 * @brief SPDU에 수납된 서명자인증서의 공개키를 재구성한다.
 * @param[in] work SPDU 작업정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ossl_SignerPublicKeyReconstruction(struct Dot2SPDUProcessWork *work)
{
  /*
   * 본 SPDU를 처리하면서 새롭게 할당된 서명자엔트리정보 (첫 수신된 서명자인증서이므로)
   */
  struct Dot2EECertCacheEntry *new_signer_entry = work->data.new_signer_entry;
  assert(new_signer_entry);

  /*
   * 공개키 재구성 연산에 입력되는 해시값(=H(CertU))를 계산한다.
   */
  struct Dot2SHA256 h_input;
  dot2_ossl_CalculateKeyReconstructionHashInput_1(new_signer_entry->cert,
                                                  new_signer_entry->cert_size,
                                                  &(new_signer_entry->issuer->cert_h),
                                                  &h_input);

  /*
   * 공개키를 재구성한다.
   */
  int ret;
  EC_KEY *eck_issuer_pub_key = new_signer_entry->issuer->contents.eck_verify_pub_key;
  assert(eck_issuer_pub_key);
  EC_KEY *eck_pub_key = dot2_ossl_ReconstructSignerPublicKey(&h_input,
                                                             &(new_signer_entry->contents.common.verify_key_indicator.key),
                                                             eck_issuer_pub_key,
                                                             &(new_signer_entry->contents.verify_pub_key),
                                                             &ret);
  if (ret < 0) {
    return ret;
  }

  /*
   * 재구성된 공개키(EC_KEY)를 서명자(인증서) 캐시 엔트리 및 SPDU 처리작업정보에 저장한다.
   */
  new_signer_entry->contents.eck_verify_pub_key = eck_pub_key;
  work->data.eck_signer_pub_key = EC_KEY_dup(eck_pub_key);
  assert(work->data.eck_signer_pub_key);
  return kDot2Result_Success;
}
#endif
