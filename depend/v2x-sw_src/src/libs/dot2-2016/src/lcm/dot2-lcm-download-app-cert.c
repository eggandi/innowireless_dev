/** 
  * @file 
  * @brief 응용인증서 다운로드 관련 구현
  * @date 2022-07-26 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "dot2-lcm-inline.h"
#if defined(_FFASN1C_)
#include "dot2-ffasn1c.h"
#include "dot2-ffasn1c-inline.h"
#elif defined(_OBJASN1C_)
#include "dot2-objasn1c.h"
#include "dot2-objasn1c-inline.h"
#else
#error "3rd party asn.1 library is not defined"
#endif


/**
 * @brief RA로부터 응용인증서를 다운로드한다.
 * @param[in] params 응용인증서 다운로드 요청 파라미터
 * @param[in] res 응용인증서 다운로드 결과가 저장될 구조체 포인터
 *
 * 응용인증서발급요청문을 생성하여 RA에 전송하고 응답문을 수신하여 결과를 반환한다.
 */
void INTERNAL
dot2_DownloadAppCert(struct Dot2AppCertDownloadRequestParams *params, struct Dot2AppCertDownloadResult *res)
{
  Log(kDot2LogLevel_Event, "Download app cert\n");

  uint8_t *req = NULL;
  Dot2SPDUSize req_size;
  char *cmhf_name = NULL;
  uint8_t *cmhf = NULL;
  Dot2CMHFSize cmhf_size;
  struct Dot2HTTPSMessage zip_resp = { NULL, 0 };
  struct Dot2UnzipCertDownloadResponse unzip_resp = { NULL, 0 };

  /*
   * 인증서 다운로드 요청을 위해 필요한 정보들을 MIB에서 가져온다.
   */
  struct Dot2CertRequestInfo cr_info;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  int ret = dot2_GetCertRequestInfo(dot2_GetCurrentTime32(), &cr_info);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if (ret < 0) {
    goto err;
  }
  if (cr_info.https.rca_tls_cert_file_path == NULL) {
    Err("Fail to download app cert - no https connection info\n");
    ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    goto err;
  }
  if (cr_info.tmp_zip_file_path == NULL) {
    Err("Fail to download app cert - no tmp zip file path\n");
    ret = -kDot2Result_LCM_NoSufficientCertRequestInfo;
    goto err;
  }

  /*
   * 응용인증서 발급요청문에 대한 H8 문자열을 계산한다 - 요청파일명에 사용된다.
   */
  char provisioning_req_h8_str[DOT2_H8_HEX_STR_LEN+1]; // H8 hexstring + '\0'
  dot2_ConvertOctsToHexStr(params->common.req_h8, 8, provisioning_req_h8_str);
  provisioning_req_h8_str[DOT2_H8_HEX_STR_LEN] = '\0';

  /*
   * 다운로드요청문에 수납할 요청파일명을 구한다.
   * 요청파일명 형식 : [0-9A-F]{16}.zip = "H8(발급요청문)" + ".zip" (예: 3339ab342cef1139.zip)
   */
  char req_filename[DOT2_H8_HEX_STR_LEN+4+1]; // "H8(발급요청문)" + ".zip" + '\0'
  memcpy(req_filename, provisioning_req_h8_str, DOT2_H8_HEX_STR_LEN);
  memcpy(req_filename + DOT2_H8_HEX_STR_LEN, ".zip", 4);
  req_filename[sizeof(req_filename) - 1] = '\0';

#ifdef _UNIT_TEST_
  // 요청파일명을 저장한다 -> 테스트코드에서 요청파일명이 제대로 만들어졌는지 체크한다.
  memset(g_dot2_mib.lcm.test.app_cert.res.down_req_filename, 0, sizeof(g_dot2_mib.lcm.test.app_cert.res.down_req_filename));
  memcpy(g_dot2_mib.lcm.test.app_cert.res.down_req_filename, req_filename, strlen(req_filename));
#endif

  /*
   * 응용인증서 다운로드요청문을 생성한다.
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
   * RA에게 응용인증서다운로드요청문을 전송하고 응용인증서가 포함된 압축파일을 다운로드한다.
   * 압축파일 내에는 응용인증서 다운로드응답문이 들어 있다.
   */
  char *rca_cert_path = cr_info.https.rca_tls_cert_file_path;
  ret = dot2_HTTPS_GET(params->common.cert_dl_url, rca_cert_path, req, req_size, NULL, NULL, &zip_resp);
  if (ret < 0) {
    goto err;
  }

  /*
   * 압축파일의 압축을 해제하여 응용인증서 다운로드응답문을 추출한다.
   */
  ret = dot2_UnzipSingleCertDownloadResponseFile(cr_info.tmp_zip_file_path,
                                                 zip_resp.octs,
                                                 zip_resp.len,
                                                 &unzip_resp);
  if (ret < 0) {
    goto err;
  }

#ifdef _UNIT_TEST_
  // 압축해제한 결과를 저장한다 -> 테스트코드에서 제대로 압축해제되었는지 비교한다.
  g_dot2_mib.lcm.test.app_cert.res.down_resp_size = unzip_resp.len;
  memcpy(g_dot2_mib.lcm.test.app_cert.res.down_resp, unzip_resp.octs, unzip_resp.len);
  // 테스트코드의 제어에 따라 첫번째 다운로드응답문을 테스트벡터로 강제 교체한다 -> -> 테스트벡터 조작으로 인한 영향을 살피기 위해
  if (g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace) {
    unzip_resp.len = g_dot2_mib.lcm.test.app_cert.tv.down_resp_size;
    memcpy(unzip_resp.octs, g_dot2_mib.lcm.test.app_cert.tv.down_resp, unzip_resp.len);
  }
#endif

  /*
   * 수신된 응용인증서 다운로드응답문을 처리한다 -> 발급된 응용인증서바이트열, 개인키 재구성값을 추출한다.
   */
  struct Dot2ECPrivateKey recon_priv;
  struct Dot2Cert app_cert;
  ret = dot2_ProcessCertDownloadResponse(kDot2CMHType_Application,
                                         unzip_resp.octs,
                                         unzip_resp.len,
                                         &cr_info,
                                         &(params->common.cert_enc_priv_key),
                                         NULL, // 미사용
                                         0, // 미사용
                                         0, // 미사용
                                         &recon_priv,
                                         &app_cert);
  if (ret < 0) {
    goto err;
  }

  /*
   * 응용인증서에 대한 CMHF를 생성한다.
   */
  struct Dot2ECPrivateKey priv_key;
  ret = dot2_MakeSequentialCMHFforImplicitCert_2(kDot2CMHType_Application,
                                                 &(params->common.verify_priv_key),
                                                 &recon_priv,
                                                 &app_cert,
                                                 &(cr_info.pca.cert_h),
                                                 &(cr_info.pca.pub_key),
                                                 &cmhf_name,
                                                 &cmhf,
                                                 &cmhf_size,
                                                 &priv_key);
  if (ret < 0) {
    goto err;
  }

  /*
   * 응용인증서, 개인키, 개인키재구성값 파일명(확장자 제외)을 설정한다. = "H8(인증서)" 로 설정한다.
   */
  char cert_h8_str[DOT2_H8_HEX_STR_LEN+1];
  struct Dot2SHA256 app_cert_h;
  SHA256(app_cert.octs, app_cert.size, app_cert_h.octs);
  dot2_ConvertOctsToHexStr(DOT2_GET_SHA256_H8(app_cert_h.octs), 8, cert_h8_str);
  cert_h8_str[DOT2_H8_HEX_STR_LEN] = '\0';

  /*
   * 결과를 반환한다.
   */
  res->ret = kDot2Result_Success;
  res->common.cmhf_name = cmhf_name;
  res->common.cmhf = cmhf;
  res->common.cmhf_size = cmhf_size;
  if (params->return_options == true) {
    memcpy(res->options.dir_name, provisioning_req_h8_str, DOT2_H8_HEX_STR_LEN);
    dot2_SetAppCertFileName(cert_h8_str, res->options.cert_filename);
    dot2_SetAppCertPrivKeyFileName(cert_h8_str, res->options.priv_key_filename);
    dot2_SetAppCertReconPrivFileName(cert_h8_str, res->options.recon_priv_filename);
    memcpy(&(res->options.cert), &app_cert, sizeof(struct Dot2Cert));
    memcpy(&(res->options.recon_priv), &recon_priv, sizeof(struct Dot2ECPrivateKey));
    memcpy(&(res->options.priv_key), &priv_key, sizeof(struct Dot2ECPrivateKey));
  }

  free(req);
  free(zip_resp.octs);
  free(unzip_resp.octs);
  dot2_ClearCertRequestInfo(&cr_info);
  Log(kDot2LogLevel_Event, "Success to download app cert\n");
  return;

err:
  res->ret = ret;
  if (req) { free(req); }
  if (cmhf_name) { free(cmhf_name); }
  if (cmhf) { free(cmhf); }
  if (zip_resp.octs) { free(zip_resp.octs); }
  if (unzip_resp.octs) { free(unzip_resp.octs); }
  dot2_ClearCertRequestInfo(&cr_info);
}

