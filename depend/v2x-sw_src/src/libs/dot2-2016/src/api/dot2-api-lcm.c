/** 
  * @file 
  * @brief dot2 라이브러리의 LCM 관련 API 구현 파일
  * @date 2022-04-30 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "lcm/dot2-lcm.h"
#include "lcm/dot2-lcm-inline.h"
#include "spdu/dot2-spdu-inline.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief LCM 동작을 위한 설정을 수행한다(상세 내용 API 매뉴얼 참조)
 * @param[in] type 설정 유형
 * @param[in] cfg_str 설정 문자열
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int OPEN_API Dot2_ConfigLCM(Dot2LCMConfigType type, const char *cfg_str)
{
  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot2_CheckLCMConfigType(type) == false) {
    Err("Fail to config LCM - invalid type: %u\n", type);
    return -kDot2Result_LCM_InvalidConfigType;
  }
  if (cfg_str == NULL) {
    Err("Fail to config LCM - Null parameters\n");
    return -kDot2Result_NullParameters;
  }

  /*
   * LCM 설정한다.
   */
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  int ret = dot2_ConfigLCM(type, cfg_str);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  return ret;
}


/**
 * @brief 등록인증서발급요청문 생성 요청 파라미터의 유효성을 체크한다.
 * @param[in] params 유효성을 체크할 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckECRequestConstructParams(struct Dot2ECRequestConstructParams *params)
{
  if (params->valid_period.duration.type > kDot2CertDurationType_Max) {
    return -kDot2Result_LCM_InvalidCertDurationType;
  }
  if (params->valid_region.region_num > kDot2IdentifiedRegionNum_Max) {
    return -kDot2Result_LCM_InvalidCertRegionNum;
  }
  if (params->permissions.num > kDot2CertPermissionNum_Max) {
    return -kDot2Result_LCM_InvalidCertPermissionNum;
  }
  return kDot2Result_Success;
}


/**
 * @brief 등록인증서(Enrollment certificate) 발급요청문의 생성을 요청한다(상세 내용 API 매뉴얼 참조)
 * @param[in] params 등록인증서 발급요청문의 생성을 위한 파라미터
 * @return 등록인증서 발급요청문 생성 결과
 */
struct Dot2ECRequestConstructResult OPEN_API Dot2_ConstructECRequest(struct Dot2ECRequestConstructParams *params)
{
  Log(kDot2LogLevel_Event, "Construct ECRequest\n");
  struct Dot2ECRequestConstructResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  res.ret = dot2_CheckECRequestConstructParams(params);
  if (res.ret < 0) {
    return res;
  }

  /*
   * 어플리케이션이 생성 시각 및 인증서 유효기간 시작시점을 전달하지 않았으면, 직접 구한다.
   */
  Dot2Time32 current = dot2_GetCurrentTime32();
  if (params->time == 0) {
    params->time = current;
  }
  if (params->valid_period.start == 0) {
    params->valid_period.start = current;
  }

  /*
   * 초기 개인키/공개키를 생성한다.
   *  - 이 개인키는 나중에 ECResponse를 처리하면서 재구성되며, 추후 서비스 인증서 발급요청문에 서명하는데 사용된다.
   * 등록인증서 발급요청문을 생성한다.
   */
  struct Dot2ECKeyPair init_key_pair;
  res.ret = dot2_ossl_GenerateECKeyPair(&init_key_pair);
  if (res.ret == kDot2Result_Success) {
    dot2_ConstructECRequest(params, &init_key_pair, &res);
  }
  return res;
}


/**
 * @brief 등록인증서발급응답문 처리 요청 파라미터의 유효성을 체크한다.
 * @param[in] params 유효성을 체크할 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckECResponseProcessParams(struct Dot2ECResponseProcessParams *params)
{
  if (params->lccf == NULL) {
    return -kDot2Result_NullParameters;
  }
  if ((params->ec_resp) &&
      (dot2_CheckSPDUSize(params->ec_resp_size) == false)) {
    return -kDot2Result_LCM_InvalidSPDUSize;
  }
  if ((dot2_CheckCertSize(params->ec.size) == false) ||
      (dot2_CheckCertSize(params->eca_cert.size) == false) ||
      (dot2_CheckCertSize(params->ra_cert.size) == false) ||
      (dot2_CheckCertSize(params->rca_cert.size) == false)) {
    return -kDot2Result_LCM_InvalidCertSize;
  }
  if (dot2_CheckLCCFSize(params->lccf_size) < 0) {
    return -kDot2Result_LCM_InvalidLCCFSize;
  }
  return kDot2Result_Success;
}


/**
 * @brief 등록인증서(Enrollment certificate) 발급응답문의 처리를 요청한다(상세 내용 API 매뉴얼 참조)
 * @param[in] params 등록인증서 발급응답문의 처리를 위한 파라미터
 * @return 등록인증서 발급응답문 처리 결과
 */
struct Dot2ECResponseProcessResult OPEN_API Dot2_ProcessECResponse(struct Dot2ECResponseProcessParams *params)
{
  Log(kDot2LogLevel_Event, "Process ECResponse\n");
  struct Dot2ECResponseProcessResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to process ECResponse - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  res.ret = dot2_CheckECResponseProcessParams(params);
  if (res.ret < 0) {
    Err("Fail to process ECResponse - invalid params\n");
    return res;
  }

  /*
   * 등록인증서 발급응답문을 처리한다.
   */
  dot2_ProcessECResponse(params, &res);
  return res;
}


/**
 * @brief 인증서다운로드요청 공통 파라미터의 유효성을 체크한다.
 * @param[in] params 유효성을 체크할 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckCertDownloadRequestParams(struct Dot2CertDownloadRequestParams *params)
{
  return params->cert_dl_url ? kDot2Result_Success : -kDot2Result_NullParameters;
}


/**
 * @brief 응용인증서 다운로드요청 파라미터의 유효성을 체크한다.
 * @param[in] params 유효성을 체크할 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckAppCertDownloadRequestParams(struct Dot2AppCertDownloadRequestParams *params)
{
  return dot2_CheckCertDownloadRequestParams(&(params->common));
}


/**
 * @brief 익명/식별인증서 다운로드요청 파라미터의 유효성을 체크한다.
 * @param[in] params 유효성을 체크할 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckPseudonymIdCertDownloadRequestParams(struct Dot2PseudonymIdCertDownloadRequestParams *params)
{
  return dot2_CheckCertDownloadRequestParams(&(params->common));
}


/**
 * @brief 인증서 다운로드일정정보 다운로드요청 파라미터의 유효성을 체크한다. (대상: 익명, 식별 인증서)
 * @param[in] params 유효성을 체크할 파라미터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckCertDownloadInfoRequestParams(struct Dot2CertDownloadInfoRequestParams *params)
{
  return params->cert_dl_url ? kDot2Result_Success : -kDot2Result_NullParameters;
}


/**
 * @brief RA에게 응용인증서 발급을 요청한다 (상세 내용 API 매뉴얼 참조)
 * @param[in] params 인증서 발급요청 파라미터
 * @return 응용인증서 발급요청 처리 결과
 */
struct Dot2AppCertProvisioningRequestResult OPEN_API
Dot2_RequestAppCertProvisioning(struct Dot2CertProvisioningRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Request app cert provisioning\n");
  struct Dot2AppCertProvisioningRequestResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to request app cert provisioning - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }

  /*
   * 응용인증서 발급을 요청한다.
   */
  dot2_RequestAppCertProvisioning(params, &res);
  return res;
}


/**
 * @brief RA에게 익명인증서 발급을 요청한다 (상세 내용 API 매뉴얼 참조)
 * @param[in] params 인증서 발급요청 파라미터
 * @return 익명인증서 발급요청 처리 결과
 */
struct Dot2PseudonymIdCertProvisioningRequestResult OPEN_API
Dot2_RequestPseudonymCertProvisioning(struct Dot2CertProvisioningRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Request pseudonym cert provisioning\n");
  struct Dot2PseudonymIdCertProvisioningRequestResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to request pseudonym cert provisioning - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }

  /*
   * 익명인증서 발급을 요청한다.
   */
  dot2_RequestPseudonymCertProvisioning(params, &res);
  return res;
}


/**
 * @brief RA에게 식별인증서 발급을 요청한다 (상세 내용 API 매뉴얼 참조)
 * @param[in] params 인증서 발급요청 파라미터
 * @return 식별인증서 발급요청 처리 결과
 */
struct Dot2PseudonymIdCertProvisioningRequestResult OPEN_API
Dot2_RequestIdCertProvisioning(struct Dot2CertProvisioningRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Request id cert provisioning\n");
  struct Dot2PseudonymIdCertProvisioningRequestResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to request id cert provisioning - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }

  /*
   * 식별인증서 발급을 요청한다.
   */
  dot2_RequestIdCertProvisioning(params, &res);
  return res;
}


/**
 * @brief RA로부터 응용인증서를 다운로드한다 (상세 내용 API 매뉴얼 참조)
 * @param[in] params 응용인증서 다운로드 요청 파라미터
 * @return 응용인증서 다운로드 결과
 */
struct Dot2AppCertDownloadResult OPEN_API Dot2_DownloadAppCert(struct Dot2AppCertDownloadRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Download app cert\n");
  struct Dot2AppCertDownloadResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to download app cert - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  res.ret = dot2_CheckAppCertDownloadRequestParams(params);
  if (res.ret < 0) {
    Err("Fail to download app cert - invalid params\n");
    return res;
  }

  /*
   * RA로부터 응용인증서를 다운로드한다.
   */
  dot2_DownloadAppCert(params, &res);
  return res;
}


/**
 * @brief RA로부터 익명인증서 1세트를 다운로드한다 (상세 내용 API 매뉴얼 참조)
 * @param[in] params 익명인증서 다운로드 요청 파라미터
 * @return 익명인증서 다운로드 결과
 */
struct Dot2PseudonymCertDownloadResult OPEN_API
Dot2_DownloadPseudonymCert(struct Dot2PseudonymIdCertDownloadRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Download pseudonym certs\n");
  struct Dot2PseudonymCertDownloadResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to download pseudonym certs - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  res.ret = dot2_CheckPseudonymIdCertDownloadRequestParams(params);
  if (res.ret < 0) {
    Err("Fail to download pseudonym certs - invalid params\n");
    return res;
  }

  /*
   * RA로부터 익명인증서 세트를 다운로드한다.
   */
  dot2_DownloadPseudonymCert(params, &res);
  return res;
}


/**
 * @brief RA로부터 식별인증서를 다운로드한다 (상세 내용 API 매뉴얼 참조)
 * @param[in] params 식별인증서 다운로드 요청 파라미터
 * @return 식별인증서 다운로드 결과
 */
struct Dot2IdCertDownloadResult OPEN_API Dot2_DownloadIdCert(struct Dot2PseudonymIdCertDownloadRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Download id cert\n");
  struct Dot2IdCertDownloadResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to download id cert - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  res.ret = dot2_CheckPseudonymIdCertDownloadRequestParams(params);
  if (res.ret < 0) {
    Err("Fail to download id cert - invalid params\n");
    return res;
  }

  /*
   * RA로부터 식별인증서를 다운로드한다.
   */
  dot2_DownloadIdCert(params, &res);

  return res;
}


/**
 * @brief RA로부터 익명/식별인증서 다운로드일정정보를 다운로드한다.(상세 내용 API 매뉴얼 참조)
 * @param[in] params 인증서 다운로드일정정보 다운로드 파라미터
 * @return 인증서 다운로드일정정보 다운로드 결과
 */
struct Dot2CertDownloadInfoDownloadResult OPEN_API
Dot2_DownloadCertDownloadInfo(struct Dot2CertDownloadInfoRequestParams *params)
{
  Log(kDot2LogLevel_Event, "Download cert download info\n");
  struct Dot2CertDownloadInfoDownloadResult res;
  memset(&res, 0, sizeof(res));

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (params == NULL) {
    Err("Fail to download cert download info - null params\n");
    res.ret = -kDot2Result_NullParameters;
    return res;
  }
  res.ret = dot2_CheckCertDownloadInfoRequestParams(params);
  if (res.ret < 0) {
    Err("Fail to download cert download info - invalid params\n");
    return res;
  }

  /*
   * RA로부터 익명인증서 다운로드일정정보를 다운로드한다.
   */
  dot2_DownloadCertDownloadInfo(params, &res);
  return res;
}


/**
 * @brief RA에서 최신 LPF(Local Policy File)를 다운로드한다(상세 내용 API 매뉴얼 참조)
 * @param[in] current_filename 현재 가지고 있는 LPF 파일명 (NULL 가능)
 * @return 서버에서 수신된 LPF 정보
 */
struct Dot2LPFRequestResult OPEN_API Dot2_DownloadLPF(const char *current_filename)
{
  Log(kDot2LogLevel_Event, "Download LPF\n");
  struct Dot2LPFRequestResult res;
  memset(&res, 0, sizeof(res));

  /*
   * LPF를 다운로드한다.
   */
  dot2_DownloadLPF(current_filename, &res);

  /*
   * 현재 LPF 처리는 지원하지 않는다.
   */

  return res;
}


/**
 * @brief RA에서 최신 LCCF(Local Certificate Chain File)를 다운로드한다(상세 내용 API 매뉴얼 참조)
 * @param[in] current_filename 현재 가지고 있는 LCCF 파일명 (NULL 가능)
 * @return 서버에서 수신된 LCCF 정보
 */
struct Dot2LCCFRequestResult OPEN_API Dot2_DownloadLCCF(const char *current_filename)
{
  Log(kDot2LogLevel_Event, "Download LCCF\n");
  struct Dot2LCCFRequestResult res;
  memset(&res, 0, sizeof(res));

  /*
   * LCCF를 다운로드한다.
   */
  char *lccf_filename;
  uint8_t *lccf;
  Dot2LCCFSize lccf_size;
  int ret = dot2_DownloadLCCF(current_filename, &lccf_filename, &lccf, &lccf_size);
  if (ret < 0) {
    res.ret = ret;
    return res;
  }

  /*
   * LCCF에서 RCA/ICA/PCA 인증서를 추출한다.
   */
  uint8_t *rca_cert = NULL, *ica_cert = NULL, *pca_cert = NULL, *crlg_cert = NULL;
  Dot2CertSize rca_cert_size, ica_cert_size, pca_cert_size, crlg_cert_size;
#if defined(_FFASN1C_)
  ret = dot2_ffasn1c_ParseLCCF(lccf,
                               lccf_size,
                               &rca_cert,
                               &rca_cert_size,
                               &ica_cert,
                               &ica_cert_size,
                               &pca_cert,
                               &pca_cert_size,
                               &crlg_cert,
                               &crlg_cert_size);
  if (ret < 0) {
    Err("Fail to download LCCF - dot2_ffasn1c_ParseLCCF() failed\n");
    goto err;
  }
#elif defined(_OBJASN1C_)
  ret = dot2_objasn1c_ParseLCCF(lccf,
                                lccf_size,
                                &rca_cert,
                                &rca_cert_size,
                                &ica_cert,
                                &ica_cert_size,
                                &pca_cert,
                                &pca_cert_size,
                                &crlg_cert,
                                &crlg_cert_size);
  if (ret < 0) {
    Err("Fail to download LCCF - dot2_objasn1c_ParseLCCF() failed\n");
    goto err;
  }
#else
#error "3rd party asn.1 library is not defined"
#endif

  /*
   * LCCF 내 인증서들을 SCC 정보리스트에 추가하여, 체인이 잘 구성되고 검증되는지 확인한다.
   * pca/ra/eca -> ica -> rca
   * - 기존에 저장된 인증서들과 동일한 경우 저장되지 않는다(성공이 반환된다)
   */
  if (rca_cert || ica_cert || pca_cert || crlg_cert) {
    pthread_mutex_lock(&(g_dot2_mib.mtx));
    ret = dot2_AddLCCFCertsToSCCList(rca_cert,
                                     rca_cert_size,
                                     ica_cert,
                                     ica_cert_size,
                                     pca_cert,
                                     pca_cert_size,
                                     crlg_cert,
                                     crlg_cert_size);
    pthread_mutex_unlock(&(g_dot2_mib.mtx));
    if (ret < 0) {
      Err("Fail to download LCCF - cannot add LCCF cert to SCC list\n");
      goto err;
    }
  }

  /*
   * 결과를 반환한다.
   */
  res.ret = kDot2Result_Success;
  res.lccf_filename = lccf_filename;
  res.lccf = lccf;
  res.lccf_size = lccf_size;
  if (rca_cert) {
    res.rca_cert = rca_cert;
    res.rca_cert_size = rca_cert_size;
  }
  if (ica_cert) {
    res.ica_cert = ica_cert;
    res.ica_cert_size = ica_cert_size;
  }
  if (pca_cert) {
    res.pca_cert = pca_cert;
    res.pca_cert_size = pca_cert_size;
  }
  if (crlg_cert) {
    res.crlg_cert = crlg_cert;
    res.crlg_cert_size = crlg_cert_size;
  }
  return res;

err:
  res.ret = ret;
  if (rca_cert) { free(rca_cert); }
  if (ica_cert) { free(ica_cert); }
  if (pca_cert) { free(pca_cert); }
  if (crlg_cert) { free(crlg_cert); }
  return res;
}


/**
 * @brief 최신 CRL(Certificate Revocation List)를 다운로드한다(상세 내용 API 매뉴얼 참조)
 * @return CRL 다운로드 결과
 */
struct Dot2CRLDownloadResult OPEN_API Dot2_DownloadCRL(void)
{
  Log(kDot2LogLevel_Event, "Download CRL\n");

  struct Dot2CRLDownloadResult res;
  memset(&res, 0, sizeof(res));

  /*
   * CRL을 다운로드한다.
   */
  uint8_t *crl;
  Dot2CRLSize crl_size;
  int ret = dot2_DownloadCRL(&crl);
  if (ret < 0) {
    res.ret = ret;
    return res;
  }
  crl_size = (Dot2CRLSize)ret;

  /*
   * 결과를 반환한다.
   */
  res.ret = kDot2Result_Success;
  res.crl = crl;
  res.crl_size = crl_size;
  return res;
}


/**
 * @brief CRL(Certificate Revocation List)을 로딩한다. (상세 내용 API 매뉴얼 참조)
 * @param[in] crl CRL 인코딩 바이트열
 * @param[in] crl_size CRL 인코딩 바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * TODO:: 추가된 CRL 엔트리의 개수를 반환하도록 수정??
 */
int OPEN_API Dot2_LoadCRL(const uint8_t *crl, Dot2CRLSize crl_size)
{
  Log(kDot2LogLevel_Event, "Load %zu-bytes CRL\n", crl_size);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (crl == NULL) {
    Err("Fail to load CRL - null parameters\n");
    return -kDot2Result_NullParameters;
  }
  if (dot2_CheckCRLSize(crl_size) == false) {
    Err("Fail to load CRL - invalid CRL size %zu\n", crl_size);
    return -kDot2Result_CRL_InvalidSize;
  }

  pthread_mutex_lock(&(g_dot2_mib.mtx));

  /*
   * CRL을 처리한다 - CRL 내 인증서폐기정보들이 CRL 테이블에 저장된다.
   */
#if defined(_FFASN1C_)
  int ret = dot2_ffasn1c_ProcessCRL(crl, crl_size);
#elif defined(_OBJASN1C_)
  int ret = dot2_objasn1c_ProcessCRL(crl, crl_size);
#else
#error "3rd party asn.1 library is not defined"
#endif

  pthread_mutex_unlock(&(g_dot2_mib.mtx));

  return ret;
}


/**
 * @brief CRL(Certificate Revocation List) 파일을 로딩한다. (상세 내용 API 매뉴얼 참조)
 * @param[in] file_path CRL 인코딩 바이트열이 저장된 파일 경로
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * TODO:: 추가된 CRL 엔트리의 개수를 반환하도록 수정??
 */
int OPEN_API Dot2_LoadCRLFile(const char *file_path)
{
  /*
   * 파라미터 유효성을 체크한다.
   */
  if (file_path == NULL) {
    Err("Fail to load CRL file - null parameters\n");
    return -kDot2Result_NullParameters;
  }

  Log(kDot2LogLevel_Event, "Load CRL file (%s)\n", file_path);

  /*
   * 파일에서 CRL을 읽어들인다.
   */
  uint8_t *crl;
  int ret = dot2_ImportFile_2(file_path, &crl, kDot2CRLSize_Min, kDot2CRLSize_Max);
  if (ret < 0) {
    Err("Fail to load CRL file - dot2_ImportFile_2() failed\n");
    return ret;
  }
  Dot2CRLSize crl_size = (Dot2CRLSize)ret;

  pthread_mutex_lock(&(g_dot2_mib.mtx));

  /*
   * CRL을 처리한다 - CRL 내 인증서폐기정보들이 CRL 테이블에 저장된다.
   */
#if defined(_FFASN1C_)
  ret = dot2_ffasn1c_ProcessCRL(crl, crl_size);
#elif defined(_OBJASN1C_)
  ret = dot2_objasn1c_ProcessCRL(crl, crl_size);
#else
#error "3rd party asn.1 library is not defined"
#endif

  pthread_mutex_unlock(&(g_dot2_mib.mtx));

  free(crl);
  return ret;
}
