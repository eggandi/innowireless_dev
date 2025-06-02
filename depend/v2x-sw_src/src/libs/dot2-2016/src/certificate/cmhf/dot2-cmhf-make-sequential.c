/** 
  * @file 
  * @brief Sequential CMHF 생성 관련 구현
  * @date 2022-07-14 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "certificate/cmhf/dot2-cmhf.h"
#if defined(_FFASN1C_)
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "asn1/objasn1c/dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief Sequential CMHF 버퍼에 정보를 채운다.
 * @param[in] cmh_type CMH 유형
 * @param[in] cert 인증서바이트열
 * @param[in] cert_h 인증서 해시값
 * @param[in] issuer_h 상위인증서 해시값
 * @param[in] priv_key 개인키
 * @param[in] contents 인증서컨텐츠정보
 * @param[in] cmhf_buf_size CMHF 버퍼 길이
 * @param[out] cmhf_buf 정보를 채울 CMHF 버퍼
 * @return 성공 시 채워진 정보의 길이, 실패 시 결과코드(-Dot2ResultCode)
 */
static int dot2_FillSequentialCMHF(
  Dot2CMHType cmh_type,
  const struct Dot2Cert *cert,
  const struct Dot2SHA256 *cert_h,
  const struct Dot2SHA256 *issuer_h,
  struct Dot2ECPrivateKey *priv_key,
  struct Dot2EECertContents *contents,
  int cmhf_buf_size,
  uint8_t *cmhf_buf)
{
  Log(kDot2LogLevel_Event, "Fill sequential CMHF\n");

  struct Dot2SequentialCMHFInfo *info = (struct Dot2SequentialCMHFInfo *)cmhf_buf;
  uint8_t *ptr = cmhf_buf;
  int remained = cmhf_buf_size;

  /*
   * 매직 넘버를 저장한다.
   */
  if (remained < (int)sizeof(uint32_t)) {
    return -kDot2Result_CMHF_TooLong;
  }
  info->magic_number = htonl(CMHF_MAGIC_NUMBER);
  ptr += sizeof(uint32_t);
  remained -= sizeof(uint32_t);

  /*
   * CMHF 공통정보를 채운다.
   */
  int len = dot2_FillCMHFCommonInfo(cmh_type, issuer_h, contents, remained, ptr);
  if (len < 0) {
    return len;
  }
  ptr += len;
  remained -= len;

  /*
   * CMHF 개별정보를 채운다.
   */
  len = dot2_FillCMHFIndividualInfo(cert, cert_h, priv_key, contents, remained, ptr);
  if (len < 0) {
    return len;
  }
  ptr += len;
  remained -= len;

  /*
   * 현재까지 채워진 정보에 대한 해시를 계산하여 마지막에 H8 값을 채운다.
   */
  uint8_t h[DOT2_SHA_256_LEN];
  SHA256(cmhf_buf, cmhf_buf_size - remained, h);
  memcpy(ptr, DOT2_GET_SHA256_H8(h), 8);
  remained -= 8;

  return (cmhf_buf_size - remained);
}


/**
 * @brief Implicit 인증서에 대한 Sequential CMHF를 생성한다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (app, id, enrol 만 가능하다)
 * @param[in] init_priv_key 초기 개인키
 * @param[in] recon_priv 개인키 재구성값
 * @param[in] cert 인증서바이트열
 * @param[in] issuer 상위인증서바이트열
 * @param[out] cmhf_name 생성된 CMHF의 이름이 저장될 버퍼 포인터
 * @param[out] cmhf 생성된 CMHF가 저장될 버퍼 포인터
 * @param[out] cmhf_size 생성된 CMHF의 길이가 저장될 버퍼 포인터
 * @param[out] priv_key 재구성된 개인키가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라,
 * EE의 Sequential 인증서는 Application, Identification, Enrollment 인증서가 해당된다.
 */
int INTERNAL dot2_MakeSequentialCMHFforImplicitCert_1(
  Dot2CMHType cmh_type,
  const struct Dot2ECPrivateKey *init_priv_key,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2Cert *cert,
  const struct Dot2Cert *issuer,
  char **cmhf_name,
  uint8_t **cmhf,
  Dot2CMHFSize *cmhf_size,
  struct Dot2ECPrivateKey *priv_key)
{
  Log(kDot2LogLevel_Event, "Make sequential CMHF for implicit cert 1 (for App, Id, Enrol cert)\n");

  /*
   * 상위인증서 해시를 계산한다.
   */
  struct Dot2SHA256 issuer_h;
  SHA256(issuer->octs, issuer->size, issuer_h.octs);

  /*
   * 상위인증서를 디코딩/파싱하여 인증서컨텐츠정보를 얻는다.
   */
  struct Dot2Signature sign;
  struct Dot2SCCCertContents issuer_contents;
#if defined(_FFASN1C_)
  int ret = dot2_ffasn1c_ParseSCCCertContents(issuer->octs, issuer->size, &issuer_contents, &sign);
#elif defined(_OBJASN1C_)
  int ret = dot2_objasn1c_ParseSCCCertContents(issuer->octs, issuer->size, &issuer_contents, &sign);
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (ret < 0) {
    return ret;
  }

  return dot2_MakeSequentialCMHFforImplicitCert_2(cmh_type,
                                                  init_priv_key,
                                                  recon_priv,
                                                  cert,
                                                  &issuer_h,
                                                  &(issuer_contents.common.verify_key_indicator.key),
                                                  cmhf_name,
                                                  cmhf,
                                                  cmhf_size,
                                                  priv_key);
}


/**
 * @brief Implicit 인증서에 대한 Sequential CMHF를 생성한다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (app, id, enrol 만 가능하다)
 * @param[in] init_priv_key 초기 개인키
 * @param[in] recon_priv 개인키 재구성값
 * @param[in] cert 인증서바이트열
 * @param[in] issuer_h 상위인증서바이트열 해시
 * @param[in] issuer_pub_key 상위인증서 공개키
 * @param[out] cmhf_name 생성된 CMHF의 이름이 저장될 버퍼 포인터
 * @param[out] cmhf 생성된 CMHF가 저장될 버퍼 포인터
 * @param[out] cmhf_size 생성된 CMHF의 길이가 저장될 버퍼 포인터
 * @param[out] priv_key 재구성된 개인키가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라,
 * EE의 Sequential 인증서는 Application, Identification, Enrollment 인증서가 해당된다.
 */
int INTERNAL dot2_MakeSequentialCMHFforImplicitCert_2(
  Dot2CMHType cmh_type,
  const struct Dot2ECPrivateKey *init_priv_key,
  const struct Dot2ECPrivateKey *recon_priv,
  const struct Dot2Cert *cert,
  const struct Dot2SHA256 *issuer_h,
  const struct Dot2ECPublicKey *issuer_pub_key,
  char **cmhf_name,
  uint8_t **cmhf,
  Dot2CMHFSize *cmhf_size,
  struct Dot2ECPrivateKey *priv_key)
{
  Log(kDot2LogLevel_Event, "Make sequential CMHF for implicit cert 2 (for App, Id, Enrol cert)\n");

  char *_cmhf_name = NULL;
  uint8_t *_cmhf = NULL;
  Dot2CMHFSize _cmhf_size = kDot2CMHFSize_Max;
  EC_KEY *eck_priv_key = NULL;
  EC_KEY *eck_pub_key = NULL;

  /*
   * 인증서 해시를 계산한다.
   */
  struct Dot2SHA256 cert_h;
  SHA256(cert->octs, cert->size, cert_h.octs);

  /*
   * 개인키를 재구성한다.
   */
  int ret;
  eck_priv_key = dot2_ossl_ReconstructImplicitCertPrivateKey_1(init_priv_key,
                                                               recon_priv,
                                                               cert,
                                                               issuer_h,
                                                               priv_key,
                                                               &ret);
  if (eck_priv_key == NULL) {
    Err("Fail to make sequential CMHF - dot2_ossl_ReconstructImplicitCertPrivateKey_1() failed\n");
    return ret;
  }

  /*
   * 인증서를 디코딩/파싱하여 인증서컨텐츠정보를 얻는다.
   */
  struct Dot2EECertContents contents;
  memset(&contents, 0, sizeof(contents));
#if defined(_FFASN1C_)
  dot2Certificate *asn1_cert = dot2_ffasn1c_ParseEECertContents_1(cert->octs, cert->size, &contents, &ret);
  if (!asn1_cert) {
    goto err;
  }
  asn1_free_value(asn1_type_dot2Certificate, asn1_cert); ///< 인증서 디코딩 정보는 CMHF에 저장되지 않으므로 제거한다.
#elif defined(_OBJASN1C_)
  ret = dot2_objasn1c_ParseEECertContents_1(cert->octs, cert->size, &contents);
  if (ret < 0) {
    goto err;
  }
#else
#error "3rd party asn.1 library is not defined"
#endif


  /*
   * 공개키를 재구성한다.
   */
  struct Dot2ECPublicKey pub_key;
  eck_pub_key = dot2_ossl_ReconstructImplicitCertPublicKey_1(&(contents.common.verify_key_indicator.key),
                                                             cert,
                                                             issuer_h,
                                                             issuer_pub_key,
                                                             &pub_key,
                                                             &ret);
  if (eck_pub_key == NULL) {
    Err("Fail to make sequential CMHF - dot2_ossl_ReconstructImplicitCertPublicKey_1() failed\n");
    goto err;
  }

  /*
   * 재구성된 개인키와 공개키의 쌍이 맞는지 확인한다.
   */
  if (dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key) == false) {
    Err("Fail to make sequential CMHF - dot2_ossl_CheckECKEYKeyPair() failed\n");
    ret = -kDot2Result_OSSL_InvalidReconstructedKeyPair;
    goto err;
  }

  /*
   * CMHF 정보가 저장될 메모리를 할당한다. 길이가 고정되어 있지 않으므로 최대길이로 할당한다.
   */
  _cmhf = (uint8_t *)calloc(1, _cmhf_size);
  if (_cmhf == NULL) {
    ret = -kDot2Result_NoMemory;
    goto err;
  }

  /*
   * CMHF 정보를 채우고 메모리 길이를 재조정한다.
   */
  ret = dot2_FillSequentialCMHF(cmh_type, cert, &cert_h, issuer_h, priv_key, &contents, (int)_cmhf_size, _cmhf);
  if (ret < 0) {
    goto err;
  }
  _cmhf_size = ret;
  _cmhf = realloc(_cmhf, _cmhf_size);
  if (_cmhf == NULL) {
    goto err;
  }

  /*
   * CMHF 이름을 생성한다.
   */
  _cmhf_name = dot2_MakeCMHFName(cmh_type, kDot2PrivKeyType_Key, &contents, &ret);
  if (_cmhf_name == NULL) {
    goto err;
  }

  /*
   * 결과를 반환한다.
   *  - 개인키는 위에서 이미 반환변수에 저장되었다.
   */
  *cmhf_name = _cmhf_name;
  *cmhf = _cmhf;
  *cmhf_size = _cmhf_size;
  return kDot2Result_Success;

err:
  if (eck_priv_key) { EC_KEY_free(eck_priv_key); }
  if (eck_pub_key) { EC_KEY_free(eck_pub_key); }
  if (_cmhf) { free(_cmhf); }
  if (_cmhf_name) { free(_cmhf_name); }
  return ret;
}
