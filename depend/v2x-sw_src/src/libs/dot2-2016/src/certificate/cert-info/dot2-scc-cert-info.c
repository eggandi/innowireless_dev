/** 
  * @file 
  * @brief Service Certificate Chain에 속하는 인증서 관련 구현
  * @date 2022-07-02 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"
#include "sudo_queue.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-cert-info-inline.h"
#include "dot2-scc-cert-info.h"
#if defined(_FFASN1C_)
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "asn1/objasn1c/dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif



/**
 * @brief SCC인증서정보 테이블을 초기화한다.
 */
void INTERNAL dot2_InitSCCCertInfoTable(void)
{
  Log(kDot2LogLevel_Event, "Initialize SCC cert info table\n");
  struct Dot2SCCCertInfoTable *table = &(g_dot2_mib.scc_cert_info_table);
  dot2_InitSCCCertInfoList();
  table->ra = NULL;
}


/**
 * @brief SCC인증서정보 테이블의 내용을 제거한다.
 */
void INTERNAL dot2_ReleaseSCCCertInfoTable(void)
{
  Log(kDot2LogLevel_Event, "Release SCC cert info table\n");
  struct Dot2SCCCertInfoTable *table = &(g_dot2_mib.scc_cert_info_table);
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_ReleaseSCCCertInfoList();
  table->ra = NULL;
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}


/**
 * @brief SCC인증서컨텐츠정보의 내용을 삭제한다.
 * @param[in] contents SCC인증서컨텐츠정보
 */
void INTERNAL dot2_ClearSCCCertContents(struct Dot2SCCCertContents *contents)
{
  dot2_ClearCertCommonContents(&(contents->common));
  if (contents->eck_verify_pub_key) {
    EC_KEY_free(contents->eck_verify_pub_key);
  }
  if (contents->eck_enc_pub_key) {
    EC_KEY_free(contents->eck_enc_pub_key);
  }
  memset(contents, 0, sizeof(struct Dot2SCCCertContents));
}


/**
 * @brief SCC인증서정보 엔트리의 내용을 삭제한다.
 * @param[in] entry SCC인증서정보 엔트리
 */
void INTERNAL dot2_ClearSCCCertInfoEntry(struct Dot2SCCCertInfoEntry *entry)
{
  dot2_ClearSCCCertContents(&(entry->contents));
  if (entry->cert) {
    free(entry->cert);
    entry->cert = NULL;
  }
  entry->cert_size = 0;
  memset(&(entry->cert_h), 0, sizeof(struct Dot2SHA256));
  entry->issuer = NULL;
}


/**
 * @brief SCC인증서정보 엔트리를 할당한다.
 * @param[in] cert 인증서정보엔트리에 저장될 인증서바이트열
 * @param[in] cert_size 인증서정보엔트리에 저장될 인증서바이트열 길이
 * @retval 인증서정보엔트리 포인터: 성공
 * @retval NULL: 실패
 */
struct Dot2SCCCertInfoEntry INTERNAL * dot2_AllocateSCCCertInfoEntry(const uint8_t *cert, Dot2CertSize cert_size)
{
  struct Dot2SCCCertInfoEntry *entry = (struct Dot2SCCCertInfoEntry *)calloc(1, sizeof(struct Dot2SCCCertInfoEntry));
  if (entry) {
    entry->cert = (uint8_t *)malloc(cert_size);
    if (entry->cert) {
      memcpy(entry->cert, cert, cert_size);
      entry->cert_size = cert_size;
    } else {
      free(entry);
      return NULL;
    }
  }
  return entry;
}


/**
 * @brief SCC인증서바이트열로부터 인증서컨텐츠정보와 서명정보를 얻는다.
 * @param[in] cert 인증서바이트열
 * @param[in] cert_size 인증서바이트열의 길이
 * @param[out] contents 인증서컨텐츠정보가 저장될 구조체 포인터
 * @param[out] sign 서명정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_GetCertContentsAndSignatureFromSCCCert(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  struct Dot2SCCCertContents *contents,
  struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Get cert contents and signatuer form SCC cert\n");

  /*
   * 인증서 바이트열로부터 인증서컨텐츠정보를 추출하고,
   * 추출된 검증키(=서명검증용공개키)로부터 Openssl 형식 서명검증용공개키 및 비압축형식 공개키바이트열를 생성하여 인증서정보에 저장한다.
   *  - 이후 하위인증서의 서명을 검증하는데 사용된다
   *  - 비압축 형식의 검증키바이트열은 이후 saf5400 H/W 기반 수신 SPDU 검증 시에 사용된다. (PCA/ACA인 경우에 한해서)
   * 인증서 내에 암호화용 공개키가 포함되어 있을 경우 추출된 키로부터 Openssl 형식 공개키와 비압축형식 공개키바이트열을 생성하여 인증서정보에 저장한다.
   * V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, 인증서 내 공개키는 모두 압축 형식을 가진다.
   */
#if defined(_FFASN1C_)
  int ret = dot2_ffasn1c_ParseSCCCertContents(cert, cert_size, contents, sign);
#elif defined(_OBJASN1C_)
  int ret = dot2_objasn1c_ParseSCCCertContents(cert, cert_size, contents, sign);
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (ret < 0) {
    return ret;
  }

  struct Dot2ECPublicKey *i_key = &(contents->common.verify_key_indicator.key);
  struct Dot2ECPublicKey *pub_key = &(contents->verify_pub_key);
  contents->eck_verify_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(i_key,
                                                                                                      pub_key,
                                                                                                      &ret);
  if (contents->eck_verify_pub_key == NULL) {
    Err("Fail to get cert contents and signatuer form SCC cert - make verify pubkey(EC_KEY) failed\n");
    return ret;
  }

  if (contents->common.enc_pub_key_present) {
    struct Dot2ECPublicKey *e_key = &(contents->common.enc_pub_key);
    contents->eck_enc_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(e_key,
                                                                                                     e_key,
                                                                                                     &ret);
    if (contents->eck_enc_pub_key == NULL) {
      Err("Fail to get cert contents and signatuer form SCC cert - make encryption pubkey(EC_KEY) failed\n");
      return ret;
    }
  }

  Log(kDot2LogLevel_Event, "Success to get cert contents and signatuer form SCC cert\n");
  return ret;
}


/**
 * @brief SCC 인증서정보 리스트를 초기화한다.
 */
void INTERNAL dot2_InitSCCCertInfoList(void)
{
  Log(kDot2LogLevel_Event, "Initialize SCC cert info list\n");
  struct Dot2SCCCertInfoList *list = &(g_dot2_mib.scc_cert_info_table.scc);
  list->entry_num = 0;
  list->max_entry_num = kDot2CertInfoEntryNum_Max;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief SCC 인증서정보 리스트의 내용을 제거한다.
 */
void INTERNAL dot2_ReleaseSCCCertInfoList(void)
{
  Log(kDot2LogLevel_Event, "Release SCC cert info list\n");
  struct Dot2SCCCertInfoList *list = &(g_dot2_mib.scc_cert_info_table.scc);
  struct Dot2SCCCertInfoEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    dot2_ClearSCCCertInfoEntry(entry);
    free(entry);
  }
  list->entry_num = 0;
}


/**
 * @brief SCC 인증서 리스트 내에서 특정 HashedID8 값을 갖는 인증서정보엔트리를 찾는다.
 * @param[in] h8 찾고자 하는 인증서 HashedID8
 * @reurn 인증서정보엔트리 포인터
 * @retval NULL: 실패
 */
struct Dot2SCCCertInfoEntry INTERNAL * dot2_FindSCCCertWithHashedID8(const uint8_t *h8)
{
  struct Dot2SCCCertInfoEntry *entry;
  TAILQ_FOREACH(entry, &(g_dot2_mib.scc_cert_info_table.scc.head), entries) {
    if (memcmp(DOT2_GET_SHA256_H8(entry->cert_h.octs), h8, 8) == 0) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief Service Certificate Chain에 속한 SCC인증서의 공통컨텐츠정보가 유효한지 검증한다.
 * @param[in] contents 인증서공통컨텐츠정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_VerifySCCCertCommonContents(const struct Dot2CertCommonContents *contents)
{
  /*
   * SCC인증서의 검증키 지시자에는 공개키재구성값이 아닌 공개키가 수납되어 있어야 한다.
   */
  if (contents->verify_key_indicator.type != kDot2CertVerificationKeyIndicatorType_Key) {
    Err("Fail to verify SCC cert common contents - invalid verify key indicator type %u\n", contents->verify_key_indicator.type);
    return -kDot2Result_InvalidVerificationKeyIndicatorType;
  }
  return kDot2Result_Success;
}


/**
 * @brief Service Certificate Chain에 속한 Self-signed 인증서(=RCA)의 인증서공통컨텐츠정보가 유효한지 검증한다.
 * @param[in] contents 인증서공통컨텐츠정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_VerifySelfSignedSCCCertCommonInfo(const struct Dot2CertCommonContents *contents)
{
  Log(kDot2LogLevel_Event, "Verify self-signed SCC cert common contents\n");

  /*
   * CRL series 확인 - SCC에 속한 Self-signed 인증서는 RootCA이며, 따라서 RootCA에 해당되는 CRL series를 가져야 한다.
   */
  if (contents->crl_series != kDot2CertCRLSeries_RootCA) {
    Err("Fail to verify self-signed SCC cert common contents - invalid CRL series %u\n", contents->crl_series);
    return -kDot2Result_InvalidCertCrlSeries;
  }

  /*
   * 공통사항 확인
   */
  return dot2_VerifySCCCertCommonContents(contents);
}


/**
 * @brief Service Certificate Chain에 속한 Issuer-signed 인증서의 유효기간이 유효한지 검증한다.
 * @param[in] valid_start 인증서 유효기간 시작시점
 * @param[in] valid_end 인증서 유효기간 종료시점
 * @param[in] issuer_valid_start 상위인증서 유효기간 시작시점
 * @param[in] issuer_valid_end 상위인증서 유효기간 종료시점
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_VerifyIssuerSignedSCCCertValidTime(
  Dot2Time64 valid_start,
  Dot2Time64 valid_end,
  Dot2Time64 issuer_valid_start,
  Dot2Time64 issuer_valid_end)
{
  /*
   * 인증서의 유효기간은 상위인증서의 유효기간 내에 포함되어야 하며,
   * 유효기간 시작시점이 종료시점과 같거나 작아야 한다.
   */
  if ((valid_start >= issuer_valid_start) &&
      (valid_end <= issuer_valid_end) &&
      (valid_start <= valid_end)) {
    return kDot2Result_Success;
  }
  return -kDot2Result_InvalidCertValidTime;
}


/**
 * @brief Service Certificate Chain에 속한 Issuer-signed 인증서의 인증서공통컨텐츠정보가 유효한지 검증한다.
 * @param[in] contents 인증서공통컨텐츠정보
 * @param[in] issuer_info 상위인증서(=Issuer)의 인증서공통정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_VerifyIssuerSignedSCCCertCommonContents(
  const struct Dot2CertCommonContents *contents,
  const struct Dot2CertCommonContents *issuer_contents)
{
  Log(kDot2LogLevel_Event, "Verify issuer-signed SCC cert common contents\n");

  /*
   * CRL series 확인
   *  - 현재 SCC에 속한 Issuer-signed 인증서는 ICA,ACA/PCA,ECA,RA,MA,CRLG 이며, 따라서 이에 해당되는 CRL series를 가져야 한다.
   *  - ICA,ACA/PCA,ECA,RA : ScmsComponent CRL series
   *  - CRLG,MA : ScmsSpclComponent CRL series
   */
  if ((contents->crl_series != kDot2CertCRLSeries_ScmsComponent) &&
      (contents->crl_series != kDot2CertCRLSeries_ScmsSpclComponent)) {
    Err("Fail to verify issuer-signed SCC cert common contents - invalid CRL series %u\n", contents->crl_series);
    return -kDot2Result_InvalidCertCrlSeries;
  }

  /*
   * 인증서 유효기간이 상위인증서 유효기간 내에 포함되는지 확인한다.
   */
  int ret = dot2_VerifyIssuerSignedSCCCertValidTime(contents->valid_start,
                                                    contents->valid_end,
                                                    issuer_contents->valid_start,
                                                    issuer_contents->valid_end);
  if (ret < 0) {
    return ret;
  }

  /*
   * 공통사항 확인
   */
  return dot2_VerifySCCCertCommonContents(contents);
}


/**
 * @brief Service Certificate Chain에 속한 Self-signed 인증서(=RCA)의 인증서컨텐츠정보를 검증한다.
 * @param[in] cert 인증서바이트열
 * @param[in] cert_size 인증서바이트열의 길이
 * @param[in] contents 인증서컨텐츠정보
 * @param[in] sign 인증서 서명정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_VerifySelfSignedSCCCertContents(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  const struct Dot2SCCCertContents *contents,
  const struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Verify self-signed SCC cert contents\n");

  /*
   * 인증서 공통정보를 검증한다.
   */
  int ret = dot2_VerifySelfSignedSCCCertCommonInfo(&(contents->common));
  if (ret < 0) {
    return ret;
  }

  /*
   * 인증서 서명을 검증한다.
   * Self-signed 인증서이므로 자신의 공개키로 서명검증한다.
   */
  const uint8_t *tbs = DOT2_GET_SELF_SIGNED_CERT_TBS(cert);
  size_t tbs_size = DOT2_GET_SELF_SIGNED_EXPLICIT_CERT_TBS_SIZE(cert_size);
  struct Dot2SHA256 *issuer_h = NULL;
  EC_KEY *eck_pub_key = contents->eck_verify_pub_key;
  return dot2_ossl_VerifySignature_1(tbs, tbs_size, issuer_h, eck_pub_key, sign);
}


/**
 * @brief Service Certificate Chain에 속한 Issuer-signed 인증서(=ICA,ACA/PCA,ECA,RA,MA,CRLG)의 인증서컨텐츠정보를 검증한다.
 * @param[in] cert 인증서바이트열
 * @param[in] cert_size 인증서바이트열의 길이
 * @param[in] contents 인증서정보
 * @param[in] sign 인증서 서명정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_VerifyIssuerSignedSCCCertContents(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  const struct Dot2SCCCertContents *contents,
  const struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Verify issuer-signed SCC cert contents\n");

  /*
   * 상위인증서(=Issuer)를 찾아 인증서 공통정보를 검증하고 인증서 서명을 검증한다.
   */
  int ret = -kDot2Result_NoIssuerCert;
  struct Dot2SCCCertInfoEntry *issuer_entry = dot2_FindSCCCertWithHashedID8(contents->common.issuer.h8);
  if (issuer_entry) {
    struct Dot2SCCCertContents *issuer_contents = &(issuer_entry->contents);
    // 인증서 공통정보 검증
    ret = dot2_VerifyIssuerSignedSCCCertCommonContents(&(contents->common), &(issuer_contents->common));
    if (ret == kDot2Result_Success) {
      // 인증서 서명 검증 - Issuer-signed 인증서이므로 상위인증서의 공개키로 서명검증한다.
      const uint8_t *tbs = DOT2_GET_ISSUER_SIGNED_CERT_TBS(cert);
      size_t tbs_size = DOT2_GET_ISSUER_SIGNED_EXPLICIT_CERT_TBS_SIZE(cert_size);
      const struct Dot2SHA256 *issuer_h = &(issuer_entry->cert_h);
      EC_KEY *eck_pub_key = issuer_entry->contents.eck_verify_pub_key;
      ret = dot2_ossl_VerifySignature_1(tbs, tbs_size, issuer_h, eck_pub_key, sign);
    }
  }
  return ret;
}


/**
 * @brief Service Certificate Chain에 속한 SCC인증서컨텐츠정보의 유효성을 검증한다.
 * @param[in] cert 인증서바이트열
 * @param[in] cert_size 인증서바이트열의 길이
 * @param[in] contents 인증서컨텐츠정보
 * @param[in] sign 인증서 내 서명정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_VerifySCCCertContents(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  struct Dot2SCCCertContents *contents,
  struct Dot2Signature *sign)
{
  Log(kDot2LogLevel_Event, "Verify SCC cert contents\n");

  int ret;
  if (contents->common.issuer.type == kDot2CertIssuerIdentifierType_Self) {
    ret = dot2_VerifySelfSignedSCCCertContents(cert, cert_size, contents, sign);
  } else {
    ret = dot2_VerifyIssuerSignedSCCCertContents(cert, cert_size, contents, sign);
  }
  return ret;
}


/**
 * @brief SCC인증서정보 저장소에 SCC 인증서정보 엔트리를 추가한다.
 * @param[in] cert 인증서바이트열
 * @param[in] cert_size 인증서바이트열의 길이
 * @param[in] contents 인증서컨텐츠정보
 * @param[in] cert_h 인증서해시값
 * @param[out] err 성공시 0, 실패시 결과코드(-Dot2ResultCode)가 반환될 변수 포인터
 * @return 저장소에 추가된 인증서 정보 엔트리 포인터
 * @retval NULL: 실패
 */
static struct Dot2SCCCertInfoEntry *dot2_AddSCCCertEntry(
  const uint8_t *cert,
  Dot2CertSize cert_size,
  const struct Dot2SHA256 *cert_h,
  struct Dot2SCCCertContents *contents,
  int *err)
{
  Log(kDot2LogLevel_Event, "Add SCC cert entry\n");

  /*
   * 저장소가 가득 차 있으면 실패를 반환한다.
   */
  struct Dot2SCCCertInfoList *scc_list = &(g_dot2_mib.scc_cert_info_table.scc);
  if (scc_list->entry_num >= scc_list->max_entry_num) {
    Err("Fail to add SCC cert entry - too many entry in list (max: %u)\n", scc_list->max_entry_num);
    *err = -kDot2Result_TooManyCertsInTable;
    return NULL;
  }

  /*
   * Issuer-signed 인증서인 경우, 인증서정보 저장소에서 상위인증서 엔트리를 찾는다. (인증서엔트리에 상위인증서로 연결하기 위해)
   * Self-signed 인증서인 경우에는 어차피 상위인증서가 존재하지 않으므로 찾을 필요 없다.
   */
  struct Dot2SCCCertInfoEntry *issuer_entry = NULL;
  if (contents->common.issuer.type == kDot2CertIssuerIdentifierType_Sha256AndDigest) {
    issuer_entry = dot2_FindSCCCertWithHashedID8(contents->common.issuer.h8);
    if (!issuer_entry) {
      Err("Fail to add SCC cert entry - no issuer cert - cannot be here\n");
      *err = -kDot2Result_NoIssuerCert;
      return NULL;
    }
  }

  /*
   * 엔트리를 생성하여 리스트에 추가한다.
   */
  *err = -kDot2Result_NoMemory;
  struct Dot2SCCCertInfoEntry *entry = dot2_AllocateSCCCertInfoEntry(cert, cert_size);
  if (entry) {
    memcpy(&(entry->contents), contents, sizeof(struct Dot2SCCCertContents)); // 인증서정보 저장
    memcpy(&(entry->cert_h), cert_h, sizeof(struct Dot2SHA256)); ///< 인증서해시값 저장
    entry->issuer = issuer_entry; // Issuer(상위인증서) 연결
    TAILQ_INSERT_TAIL(&(scc_list->head), entry, entries); // 리스트에 추가
    scc_list->entry_num++;
    Log(kDot2LogLevel_Event, "Success to add SCC cert entry - entry_num: %u\n", scc_list->entry_num);
    *err = kDot2Result_Success;
  }
  return entry;
}


/**
 * @brief Service Certificate Chain에 속한 SCC인증서정보를 SCC인증서정보 저장소에 추가한다.
 * @param[in] cert 추가할 인증서 바이트열
 * @param[in] cert_size 추가할 인증서 바이트열의 길이
 * @param[out] err 실패시 결과코드(-Dot2ResultCode)가 반환될 변수 포인터
 * @return 저장소에 추가된 인증서 정보 엔트리 포인터 (사용 후 free() 되어야 한다)
 * @retval NULL: 실패
 */
struct Dot2SCCCertInfoEntry INTERNAL * dot2_AddSCCCert(const uint8_t *cert, Dot2CertSize cert_size, int *err)
{
  Log(kDot2LogLevel_Event, "Add %zu-bytes SCC cert in table\n", cert_size);

  struct Dot2SCCCertContents cert_contents;
  memset(&cert_contents, 0, sizeof(cert_contents));
  struct Dot2SCCCertInfoEntry *cert_entry = NULL;

  /*
   * 인증서의 해시값을 계산한다.
   */
  struct Dot2SHA256 cert_h;
  SHA256(cert, cert_size, cert_h.octs);

  /*
   * 헤시값 기준으로 동일한 인증서정보가 이미 테이블에 존재하면 실패한다.
   */
  cert_entry = dot2_FindSCCCertWithHashedID8(DOT2_GET_SHA256_H8(cert_h.octs));
  if (cert_entry) {
    Err("Fail to add SCC cert in table - same cert in table\n");
    *err = -kDot2Result_CERT_SameCertInTable;
    return NULL;
  }

  /*
   * 인증서바이트열로부터 인증서컨텐츠정보를 획득한다.
   */
  struct Dot2Signature cert_sign;
  int ret = dot2_GetCertContentsAndSignatureFromSCCCert(cert, cert_size, &cert_contents, &cert_sign);
  if (ret < 0) {
    goto fail;
  }

  /*
   * 인증서컨텐츠를 검증한다.
   */
  ret = dot2_VerifySCCCertContents(cert, cert_size, &cert_contents, &cert_sign);
  if (ret < 0) {
    goto fail;
  }

  /*
   * 인증서 정보를 Service Certificate Chain 인증서 리스트에 저장한다.
   *  - RA 인증서일 경우 RA 인증서정보 참조 포인터를 설정한다.
   *  - ACA/PCA 인증서일 경우 ACA/PCA 인증서정보 참조 포인터를 설정한다.
   */
  cert_entry = dot2_AddSCCCertEntry(cert, cert_size, &cert_h, &cert_contents, &ret);
  if (cert_entry == NULL) {
    goto fail;
  }

  if (cert_contents.type == kDot2SCCCertType_RA) {
    g_dot2_mib.scc_cert_info_table.ra = cert_entry;
  } else if (cert_contents.type == kDot2SCCCertType_PCA) {
    g_dot2_mib.scc_cert_info_table.pca = cert_entry;
  }
  Log(kDot2LogLevel_Event, "Success to add SCC cert in table\n");
  *err = ret;
  return cert_entry;

fail:
  dot2_ClearSCCCertContents(&cert_contents);
  *err = ret;
  return NULL;
}


/**
 * @brief 만기된 SCC 인증서들을 삭제한다.
 * @param[in] exp 기준이 되는 만기시각
 */
void INTERNAL dot2_RemoveExpiredSCCCert(Dot2Time64 exp)
{
  Log(kDot2LogLevel_Event, "Remove expired SCC cert - exp: %"PRIu64"\n", exp);
  struct Dot2SCCCertInfoTable *table = &(g_dot2_mib.scc_cert_info_table);
  struct Dot2SCCCertInfoList *list = &(table->scc);
  struct Dot2SCCCertInfoEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    if (entry->contents.common.valid_end < exp) {
      TAILQ_REMOVE(&(list->head), entry, entries);
      dot2_ClearSCCCertInfoEntry(entry);
      if (entry == table->ra) {
        table->ra = NULL;
      } else if (entry == table->pca) {
        table->pca = NULL;
      }
      list->entry_num--;
      free(entry);
    }
  }
}
