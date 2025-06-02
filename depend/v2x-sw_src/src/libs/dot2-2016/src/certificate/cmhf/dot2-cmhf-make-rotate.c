/** 
  * @file 
  * @brief Rotate CMH 생성 관련 구현
  * @date 2022-07-16 
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
 * @brief Rotate CMHF 버퍼에 정보를 채운다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (pseudonym/Id 만 가능하다)
 * @param[in] i 인증서 i 값
 * @param[in] j 인증서 j 최대값
 * @param[in] priv_key j_max+1개의 재구성된 개인키
 * @param[in] cert j_max+1개의 인증서 바이트열
 * @param[in] contents j_max+1개의 인증서 컨텐츠정보
 * @param[in] issuer_h 상위인증서 해시
 * @param[in] cmhf_buf_size CMHF 버퍼의 길이
 * @param[out] cmhf 생성된 CMHF가 저장될 버퍼 포인터
 * @return 성공 시 채워진 정보의 길이, 실패 시 결과코드(-Dot2ResultCode)
 */
static int dot2_FillRotateCMHF(
  Dot2CMHType cmh_type,
  uint32_t i,
  Dot2CertJvalue j_max,
  const struct Dot2ECPrivateKey *priv_keys,
  const struct Dot2Cert *certs,
  const struct Dot2EECertContents *contents,
  const struct Dot2SHA256 *issuer_h,
  int cmhf_buf_size,
  uint8_t *cmhf_buf)
{
  Log(kDot2LogLevel_Event, "Fill rotate CMHF\n");

  struct Dot2RotateCMHFSetInfo *info = (struct Dot2RotateCMHFSetInfo *)cmhf_buf;
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
  int len = dot2_FillCMHFCommonInfo(cmh_type, issuer_h, (contents + 0), remained, ptr);
  if (len < 0) {
    return len;
  }
  ptr += len;
  remained -= len;

  /*
   * 인증서 i 값을 저장한다.
   */
  if (remained < (int)sizeof(uint32_t)) {
    return -kDot2Result_CMHF_TooLong;
  }
  *(uint32_t *)ptr = htonl(i);
  ptr += sizeof(uint32_t);
  remained -= sizeof(uint32_t);

  /*
   * 인증서 개수를 저장한다.
   */
  if (remained < (int)sizeof(uint8_t)) {
    return -kDot2Result_CMHF_TooLong;
  }
  *ptr = (uint8_t)j_max + 1;
  ptr++;
  remained --;

  /*
   * 인증서 개수만큼의 CMHF 개별정보를 채운다.
   */
  for (unsigned int j = 0; j <= j_max; j++) {

    // (저장할) 인증서 해시를 계산한다.
    struct Dot2SHA256 cert_h;
    SHA256((certs + j)->octs, (certs + j)->size, cert_h.octs);

    // 개별정보를 채운다.
    len = dot2_FillCMHFIndividualInfo(certs + j,
                                      &cert_h,
                                      priv_keys + j,
                                      contents + j,
                                      remained,
                                      ptr);
    if (len < 0) {
      return len;
    }
    ptr += len;
    remained -= len;
  }

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
 * @brief Implicit 인증서에 대한 Rotate CMHF를 생성한다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (Pseudonym/Id 만 가능하다)
 * @param[in] i 인증서 i 값
 * @param[in] j 인증서 j 최대값
 * @param[in] exp_key 키 확장함수
 * @param[in] seed_priv 시드 개인키
 * @param[in] certs j_max+1개의 인증서 바이트열
 * @param[in] recon_privs j_max+1개의 개인키 재구성값
 * @param[in] issuer 상위인증서 바이트열
 * @param[out] cmhf_name 생성된 CMHF의 이름이 저장될 버퍼 포인터
 * @param[out] cmhf 생성된 CMHF가 저장될 버퍼 포인터
 * @param[out] cmhf_size 생성된 CMHF의 길이가 저장될 버퍼 포인터
 * @param[out] priv_keys 재구성된 개인키가 저장될 j_max+1개의 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라,
 *  - EE의 Rotate 인증서는 익명/식별 인증서가 해당된다.
 *  - 현재, 익명인증서의 경우 하나의 Rotate CMH/CMHF 당 저장되는 인증서의 개수는 20개(=kDot2CertJvalue_Max+1)이다.
 *  - 현재, 식별인증서의 경우 하나의 Rotate CMH/CMHF 당 저장되는 인증서의 개수는 1개이다.
 */
int INTERNAL dot2_MakeRotateCMHFforImplicitCert_1(
  Dot2CMHType cmh_type,
  uint32_t i,
  Dot2CertJvalue j_max,
  const struct Dot2AESKey *exp_key,
  const struct Dot2ECPrivateKey *seed_priv,
  const struct Dot2Cert *certs,
  const struct Dot2ECPrivateKey *recon_privs,
  const struct Dot2Cert *issuer,
  char **cmhf_name,
  uint8_t **cmhf,
  Dot2CMHFSize *cmhf_size,
  struct Dot2ECPrivateKey *priv_keys)
{
  Log(kDot2LogLevel_Event, "Make rotate CMHF for implicit cert 1 (for Pseudonym/Id cert)\n");

  /*
   * 상위인증서에 대한 해시를 계산한다.
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

  /*
   * CMHF를 생성한다.
   */
  return dot2_MakeRotateCMHFforImplicitCert_2(cmh_type,
                                              i,
                                              j_max,
                                              exp_key,
                                              seed_priv,
                                              certs,
                                              recon_privs,
                                              &issuer_h,
                                              &(issuer_contents.common.verify_key_indicator.key),
                                              cmhf_name,
                                              cmhf,
                                              cmhf_size,
                                              priv_keys);
}


/**
 * @brief Implicit 인증서에 대한 Rotate CMHF를 생성한다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (Pseudonym/Id 만 가능하다)
 * @param[in] i 인증서 i 값
 * @param[in] j 인증서 j 최대값
 * @param[in] exp_key 키 확장함수
 * @param[in] seed_priv 시드 개인키
 * @param[in] certs j_max+1개의 인증서 바이트열
 * @param[in] recon_privs j_max+1개의 개인키 재구성값
 * @param[in] issuer_h 상위인증서 해시
 * @param[out] cmhf_name 생성된 CMHF의 이름이 저장될 버퍼 포인터
 * @param[out] cmhf 생성된 CMHF가 저장될 버퍼 포인터
 * @param[out] cmhf_size 생성된 CMHF의 길이가 저장될 버퍼 포인터
 * @param[out] priv_keys 재구성된 개인키가 저장될 j_max+1개의 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라,
 *  - EE의 Rotate 인증서는 익명/식별 인증서가 해당된다.
 *  - 현재, 익명인증서의 경우 하나의 Rotate CMH/CMHF 당 저장되는 인증서의 개수는 20개(=kDot2CertJvalue_Max+1)이다.
 *  - 현재, 식별인증서의 경우 하나의 Rotate CMH/CMHF 당 저장되는 인증서의 개수는 1개이다.
 */
int INTERNAL dot2_MakeRotateCMHFforImplicitCert_2(
  Dot2CMHType cmh_type,
  uint32_t i,
  Dot2CertJvalue j_max,
  const struct Dot2AESKey *exp_key,
  const struct Dot2ECPrivateKey *seed_priv,
  const struct Dot2Cert *certs,
  const struct Dot2ECPrivateKey *recon_privs,
  const struct Dot2SHA256 *issuer_h,
  const struct Dot2ECPublicKey *issuer_pub_key,
  char **cmhf_name,
  uint8_t **cmhf,
  Dot2CMHFSize *cmhf_size,
  struct Dot2ECPrivateKey *priv_keys)
{
  Log(kDot2LogLevel_Event, "Make rotate CMHF for implicit cert 2 (for Pseudonym/Id cert)\n");

  /*
   * 각 인증서를 디코딩/파싱하고 대응되는 개인키를 재구성한다.
   */
  int ret;
  struct Dot2EECertContents contents[kDot2CertJvalue_Max + 1];
  for (unsigned int j = 0; j <= j_max; j++) {

    // 인증서를 디코딩/파싱하여 인증서컨텐츠정보를 얻는다.
    memset(&contents[j], 0, sizeof(struct Dot2EECertContents));
#if defined(_FFASN1C_)
    dot2Certificate *asn1_cert = dot2_ffasn1c_ParseEECertContents_1((certs + j)->octs,
                                                                    (certs + j)->size,
                                                                    &contents[j],
                                                                    &ret);
    if (!asn1_cert) {
      return ret;
    }
    asn1_free_value(asn1_type_dot2Certificate, asn1_cert); ///< 인증서 디코딩 정보는 CMHF에 저장되지 않으므로 제거한다.
#elif defined(_OBJASN1C_)
    ret = dot2_objasn1c_ParseEECertContents_1((certs + j)->octs, (certs + j)->size, &contents[j]);
    if (ret < 0) {
      return ret;
    }
#else
#error "3rd party asn.1 library is not defined"
#endif

    // 개인키를 재구성한다.
    ret = dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1(i,
                                                                 j,
                                                                 exp_key,
                                                                 seed_priv,
                                                                 recon_privs + j,
                                                                 &(contents[j].common.verify_key_indicator.key),
                                                                 certs + j,
                                                                 issuer_h,
                                                                 issuer_pub_key,
                                                                 priv_keys + j);
    if (ret < 0) {
      Err(
      "Fail to make rotate CMHF for implicit cert 2 - dot2_ossl_ReconstructImplicitCertButterflyPrivateKey_1() failed\n");
      return ret;
    }
  }

  /*
   * CMHF를 생성한다.
   */
  return dot2_MakeRotateCMHFforImplicitCert_3(cmh_type,
                                              i,
                                              j_max,
                                              priv_keys,
                                              certs,
                                              contents,
                                              issuer_h,
                                              cmhf_name,
                                              cmhf,
                                              cmhf_size);
}


/**
 * @brief Implicit 인증서에 대한 Rotate CMHF를 생성한다.
 * @param[in] cmh_type 생성하고자 하는 CMHF의 CMH 유형 (Pseudonym/Id 만 가능하다)
 * @param[in] i 인증서 i 값
 * @param[in] j 인증서 j 최대값
 * @param[in] priv_keys j_max+1개의 재구성된 개인키
 * @param[in] certs j_max+1개의 인증서 바이트열
 * @param[in] contents j_max+1개의 인증서 컨텐츠정보
 * @param[in] issuer_h 상위인증서 해시
 * @param[out] cmhf_name 생성된 CMHF의 이름이 저장될 버퍼 포인터
 * @param[out] cmhf 생성된 CMHF가 저장될 버퍼 포인터
 * @param[out] cmhf_size 생성된 CMHF의 길이가 저장될 버퍼 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라,
 *  - EE의 Rotate 인증서는 익명/식별 인증서가 해당된다.
 *  - 현재, 익명인증서의 경우 하나의 Rotate CMH/CMHF 당 저장되는 인증서의 개수는 20개(=kDot2CertJvalue_Max+1)이다.
 *  - 현재, 식별인증서의 경우 하나의 Rotate CMH/CMHF 당 저장되는 인증서의 개수는 1개이다.
 */
int INTERNAL dot2_MakeRotateCMHFforImplicitCert_3(
  Dot2CMHType cmh_type,
  uint32_t i,
  Dot2CertJvalue j_max,
  const struct Dot2ECPrivateKey *priv_keys,
  const struct Dot2Cert *certs,
  const struct Dot2EECertContents *contents,
  const struct Dot2SHA256 *issuer_h,
  char **cmhf_name,
  uint8_t **cmhf,
  Dot2CMHFSize *cmhf_size)
{
  Log(kDot2LogLevel_Event, "Make rotate CMHF for implicit cert 3 (for Pseudonym/Id cert)\n");

  /*
   * CMHF 정보가 저장될 메모리를 할당한다. 길이가 고정되어 있지 않으므로 최대길이로 할당한다.
   */
  int ret = -kDot2Result_NoMemory;
  int _cmhf_size = kDot2CMHFSize_Max;
  uint8_t *_cmhf = (uint8_t *)calloc(1, _cmhf_size);
  if (!cmhf) {
    return -kDot2Result_NoMemory;
  }

  /*
   * CMHF 정보를 채우고 길이에 맞게 할당된 메모리를 조정한다.
   */
  ret = dot2_FillRotateCMHF(cmh_type, i, j_max, priv_keys, certs, contents, issuer_h, _cmhf_size, _cmhf);
  if (ret < 0) {
    Err("Fail to make rotate CMHF for implicit cert 3 - dot2_FillRotateCMHF() failed\n");
    goto err;
  }
  _cmhf_size = ret;
  _cmhf = realloc(_cmhf, _cmhf_size);
  if (!_cmhf) {
    return -kDot2Result_NoMemory;
  }

  /*
   * CMHF 이름을 생성한다.
   */
  char *_cmhf_name = dot2_MakeCMHFName(cmh_type, kDot2PrivKeyType_Key, (contents + 0), &ret);
  if (!_cmhf_name) {
    Err("Fail to make rotate CMHF for implicit cert 3 - dot2_MakeCMHFName() failed\n");
    goto err;
  }

  *cmhf_name = _cmhf_name;
  *cmhf = _cmhf;
  *cmhf_size = (Dot2CMHFSize)_cmhf_size;
  return kDot2Result_Success;

err:
  free(_cmhf);
  return ret;
}
