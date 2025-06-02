/** 
  * @file 
  * @brief 인증서 다운로드 관련 구현
  * @date 2022-08-13 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief 인증서 다운로드응답문을 처리한다.
 * @param[in] cert_type 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] resp 인증서 다운로드응답문 바이트열 (SignedEncryptedCertificateResponse)
 * @param[in] resp_size 인증서 다운로드응답문 바이트열의 길이
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[in] cert_enc_priv_key 인증서복호화용 개인키
 * @param[in] cert_enc_exp_key 인증서복호화용 개인키 확장함수키 (cert_type=pseudonym/Id인 경우에만 사용된다)
 * @param[in] i_preiod i-period 값 (cert_type=pseudonym/Id인 경우에만 사용된다)
 * @param[in] j_value j 값 (cert_type=pseudonym/Id인 경우에만 사용된다)
 * @param[out] recon_priv 개인키 재구성값이 저장될 구조체 포인터
 * @param[out] cert 인증서 바이트열이 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 인증서 다운로드응답문에 대한 서명검증, 복호화가 수행된다.
 * 인증서 다운로드응답문 내에 포함된 인증서, 개인키 재구성값을 추출하여 반환한다.
 */
int INTERNAL dot2_ProcessCertDownloadResponse(
  Dot2CMHType cert_type,
  const uint8_t *resp,
  Dot2SPDUSize resp_size,
  struct Dot2CertRequestInfo *cr_info,
  struct Dot2ECPrivateKey *cert_enc_priv_key,
  struct Dot2AESKey *cert_enc_exp_key,
  Dot2IPeriod i_period,
  Dot2CertJvalue j_value,
  struct Dot2ECPrivateKey *recon_priv,
  struct Dot2Cert *cert)
{
  Log(kDot2LogLevel_Event, "Process cert download response\n");

  if (!resp ||
      (dot2_CheckSPDUSize(resp_size) == false)) {
    return -kDot2Result_LCM_InvalidCertDownloadResponse;
  }

  /*
   * 인증서 다운로드응답문(SignedEncryptedCertificateResponse)에서 정보를 파싱한다.
   *  - 발급응답문 내 포함된 서명, 개인키재구성값, 인증서바이트열을 추출한다.
   *  - 서명검증을 위해 ToBeSignedData 영역에 대한 해시도 함께 추출한다.
   */
  struct Dot2Signature sign;
  struct Dot2SHA256 tbs_h;
#if defined(_FFASN1C_)
  int ret = dot2_ffasn1c_ParseSignedEncryptedCertificateResponse(cert_type,
                                                                 resp,
                                                                 resp_size,
                                                                 cert_enc_priv_key,
                                                                 cert_enc_exp_key,
                                                                 i_period,
                                                                 j_value,
                                                                 &sign,
                                                                 &tbs_h,
                                                                 recon_priv,
                                                                 cert);
#elif defined(_OBJASN1C_)
  int ret = dot2_objasn1c_ParseSignedEncryptedCertificateResponse(cert_type,
                                                                  resp,
                                                                  resp_size,
                                                                  cert_enc_priv_key,
                                                                  cert_enc_exp_key,
                                                                  i_period,
                                                                  j_value,
                                                                  &sign,
                                                                  &tbs_h,
                                                                  recon_priv,
                                                                  cert);
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (ret < 0) {
    return ret;
  }

  /*
   * PCA 공개키로 인증서 다운로드응답문의 서명을 검증한다.
   *  - KISA v1.1 규격에 따르면 다운로드응답문에 서명하는 주체는 ACA/PCA이다.
   */
  ret = dot2_ossl_VerifySignature_2(&tbs_h, &(cr_info->pca.cert_h), cr_info->pca.eck_pub_key, &sign);
  if (ret < 0) {
    Err("Fail to process cert download response - dot2_ossl_VerifySignature_2() failed\n");
    return ret;
  }

  Log(kDot2LogLevel_Event, "Success to process cert download response\n");
  return kDot2Result_Success;
}



/**
 * @brief 수신된 인증서 다운로드일정정보 응답문을 처리한다.
 * @param[in] resp 인증서 다운로드일정정보 응답문 바이트열
 * @param[in] resp_size 인증서 다운로드일정정보 응답문 바이트열의 길이
 * @param[out] cert_dl_time 다운로드 가능시간이 저장될 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ProcessCertDownloadInfoResponse(const uint8_t *resp, size_t resp_size, Dot2Time32 *cert_dl_time)
{
  Log(kDot2LogLevel_Event, "Process cert download info response\n");
#if defined(_FFASN1C_)
  return dot2_ffasn1c_ParseCertDownloadInfoResponse(resp, resp_size, cert_dl_time);
#elif defined(_OBJASN1C_)
  return dot2_objasn1c_ParseCertDownloadInfoResponse(resp, resp_size, cert_dl_time);
#else
#error "3rd party asn.1 library is not defined"
#endif
}



/**
 * @brief RA로부터 인증서 다운로드일정정보를 다운로드한다.
 * @param[in] params 인증서 다운로드일정정보 다운로드 요청 파라미터
 * @param[in] res RA로부터 수신된 인증서 다운로드일정정보가 저장될 구조체 포인터
 *
 * 인증서 다운로드일정정보 다운로드요청문을 생성하여 RA에 전송하고 응답문(다운로드일정정보 포함)을 수신하여 결과를 반환한다.
 */
void INTERNAL dot2_DownloadCertDownloadInfo(
  struct Dot2CertDownloadInfoRequestParams *params,
  struct Dot2CertDownloadInfoDownloadResult *res)
{
  Log(kDot2LogLevel_Event, "Download cert download info\n");

  uint8_t *req = NULL;
  Dot2SPDUSize req_size;

  /*
   * 다운로드일정정보 요청을 위해 필요한 정보들을 MIB에서 가져온다.
   */
  struct Dot2CertRequestInfo cr_info;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  int ret = dot2_GetCertRequestInfo(dot2_GetCurrentTime32(), &cr_info);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if (ret < 0) {
    goto err;
  }
  if (cr_info.https.rca_tls_cert_file_path == NULL) {
    Err("Fail to request cert download info - no https connection info\n");
    ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    goto err;
  }

  /*
   * 다운로드일정정보 요청문에 수납할 요청파일명을 구한다.
   * 요청파일명 형식 : [0-9A-F]{16}.info = "H8(발급요청문)" + ".info" (예: 3339ab342cef1139.info)
   */
  char req_filename[DOT2_H8_HEX_STR_LEN+5+1]; // "H8(발급요청문)" + ".info" + '\0'
  memset(req_filename, 0, sizeof(req_filename));
  dot2_ConvertOctsToHexStr(params->req_h8, 8, req_filename);
  strcat(req_filename, ".info");

#ifdef _UNIT_TEST_
  // 요청파일명을 저장한다 -> 테스트코드에서 요청파일명이 제대로 만들어졌는지 체크한다.
  strcpy(g_dot2_mib.lcm.test.down_info.res.req_filename, req_filename);
#endif

  /*
   * 다운로드일정정보 요청문을 생성한다.
   */
#if defined(_FFASN1C_)
  req = dot2_ffasn1c_ConstructCertDownloadRequest(req_filename, &cr_info, &ret);
  if (req == NULL) {
    goto err;
  }
#elif defined(_OBJASN1C_)
  req = dot2_objasn1c_ConstructCertDownloadRequest(req_filename, &cr_info, &ret);
  if (req == NULL) {
    goto err;
  }
#else
#error "3rd party asn.1 library is not defined"
#endif
  req_size = (Dot2SPDUSize)ret;

  /*
   * RA에게 다운로드일정정보 요청문을 전송하고 다운로드일정정보 응답문을 수신한다.
   */
  struct Dot2HTTPSMessage resp_msg;
  char *rca_cert_path = cr_info.https.rca_tls_cert_file_path;
  ret = dot2_HTTPS_GET(params->cert_dl_url, rca_cert_path, req, req_size, NULL, NULL, &resp_msg);
  if (ret < 0) {
    goto err;
  }

  /*
   * 수신된 다운로드일정정보 응답문을 처리한다
   *  - 다운로드일정정보 응답문의 형식은 Time32(다운로드가능시간) 값에 대한 인코딩 바이트열이다.
   */
  Dot2Time32 cert_dl_time;
  ret = dot2_ProcessCertDownloadInfoResponse(resp_msg.octs, resp_msg.len, &cert_dl_time);
  if (ret < 0) {
    goto err;
  }

  /*
   * 결과를 반환한다.
   */
  time_t current_time = dot2_GetCurrentSystemTimeInSeconds();
  res->ret = kDot2Result_Success;
  res->cert_dl_time = cert_dl_time;
  res->current_time = dot2_ConvertSystemTimeToTime32(current_time);
  res->remained_cert_dl_time = (int)dot2_ConvertTime32ToSystemTimeSeconds(cert_dl_time) - (int)current_time;

  free(req);
  dot2_ClearCertRequestInfo(&cr_info);
  Log(kDot2LogLevel_Event, "Success to download cert download info\n");
  return;

err:
  res->ret = ret;
  if (req) { free(req); }
  dot2_ClearCertRequestInfo(&cr_info);
}
