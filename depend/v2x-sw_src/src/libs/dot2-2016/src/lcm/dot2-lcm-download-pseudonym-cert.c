/** 
  * @file 
  * @brief 익명인증서 다운로드 관련 구현
  * @date 2022-08-10 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

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
 * @brief RA로부터 익명인증서(들)을 다운로드한다.
 * @param[in] params 익명인증서 다운로드 요청 파라미터
 * @param[in] res 익명인증서 다운로드 결과가 저장될 구조체 포인터
 *
 * 익명인증서다운로드요청문을 생성하여 RA에 전송하고 응답문(발급된 인증서 포함)을 수신하여 결과를 반환한다.
 */
void INTERNAL dot2_DownloadPseudonymCert(
  struct Dot2PseudonymIdCertDownloadRequestParams *params,
  struct Dot2PseudonymCertDownloadResult *res)
{
  Log(kDot2LogLevel_Event, "Download pseudonym cert\n");

  uint8_t *req = NULL;
  Dot2SPDUSize req_size;
  char *cmhf_name = NULL;
  uint8_t *cmhf = NULL;
  Dot2CMHFSize cmhf_size;
  struct Dot2HTTPSMessage zip_resp = { NULL, 0 };
  struct Dot2UnzipCertDownloadResponse unzip_resp[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD];
  memset(unzip_resp, 0, sizeof(struct Dot2UnzipCertDownloadResponse) * DOT2_DEFAULT_P_CERTS_PER_I_PERIOD);

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
    Err("Fail to download pseudonym cert - no https connection info\n");
    ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    goto err;
  }
  if (cr_info.tmp_zip_file_path == NULL) {
    Err("Fail to download pseudonym cert - no tmp zip file path\n");
    ret = -kDot2Result_LCM_NoSufficientCertRequestInfo;
    goto err;
  }

  /*
   * H8(발급요청문)을 계산한다.
   */
  char provisioning_req_h8_str[DOT2_H8_HEX_STR_LEN+1]; // H8 hexstring + '\0'
  dot2_ConvertOctsToHexStr(params->common.req_h8, 8, provisioning_req_h8_str);
  provisioning_req_h8_str[DOT2_H8_HEX_STR_LEN] = '\0';

  /*
   * I-period 값을 설정한다.
   */
  Dot2IPeriod i_period;
  if (params->i_period == kDot2IPeriod_Current) {
    i_period = dot2_GetCurrentIPeriod();
#ifdef _UNIT_TEST_
    i_period = g_dot2_mib.lcm.test.pseudonym_cert.tv.i_period;
#endif
  } else if (params->i_period == kDot2IPeriod_Next) {
    i_period = dot2_GetCurrentIPeriod() + 1;
#ifdef _UNIT_TEST_
    i_period = g_dot2_mib.lcm.test.pseudonym_cert.tv.i_period;
#endif
  } else {
    i_period = params->i_period;
  }

  /*
   * 다운로드요청문에 수납할 요청파일명을 구한다.
   * 요청파일명 형식 : [0-9A-F]{16}_[0-9A-F]{1,8}.zip = "H8(발급요청문)" + '_' + "i" + ".zip" (예: 3339ab342cef1139_18D.zip)
   */
  char req_filename[DOT2_H8_HEX_STR_LEN+1+DOT2_I_PERIOD_HEX_STR_MAX_LEN+4+1]; // "H8(발급요청문)" + '_' + "i-period" + ".zip" + "\0"
  memset(req_filename, 0, sizeof(req_filename));
  memcpy(req_filename, provisioning_req_h8_str, DOT2_H8_HEX_STR_LEN);
  strcat(req_filename, "_");
  sprintf(req_filename + strlen(req_filename), "%X", i_period);
  strcat(req_filename, ".zip");

#ifdef _UNIT_TEST_
  // 요청파일명을 저장한다 -> 테스트코드에서 요청파일명이 제대로 만들어졌는지 체크한다.
  strcpy(g_dot2_mib.lcm.test.pseudonym_cert.res.down_req_filename, req_filename);
#endif

  /*
   * 다운로드요청문을 생성한다.
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
   * RA에게 익명인증서다운로드요청문을 전송하고 익명인증서가 포함된 압축파일을 다운로드한다.
   * 압축파일 내에는 익명인증서 다운로드응답문들이 들어 있다.
   */
  char *rca_cert_path = cr_info.https.rca_tls_cert_file_path;
  ret = dot2_HTTPS_GET(params->common.cert_dl_url, rca_cert_path, req, req_size, NULL, NULL, &zip_resp);
  if (ret < 0) {
    goto err;
  }

  /*
   * 압축파일의 압축을 해제하여 익명인증서 다운로드응답문들을 추출한다.
   */
  ret = dot2_UnzipMultipleCertDownloadResponseFiles(cr_info.tmp_zip_file_path,
                                                    zip_resp.octs,
                                                    zip_resp.len,
                                                    i_period,
                                                    DOT2_DEFAULT_P_CERTS_PER_I_PERIOD,
                                                    unzip_resp);
  if (ret < 0) {
    goto err;
  }

#ifdef _UNIT_TEST_
  for (unsigned int j = 0; j < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; j++) {
    // 압축해제한 결과를 저장한다 -> 테스트코드에서 제대로 압축해제되었는지 비교한다.
    g_dot2_mib.lcm.test.pseudonym_cert.res.down_resp_size[j] = unzip_resp[j].len;
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.res.down_resp[j], unzip_resp[j].octs, unzip_resp[j].len);
  }
  // 테스트코드의 제어에 따라 첫번째 다운로드응답문을 테스트벡터로 강제 교체한다 -> -> 테스트벡터 조작으로 인한 영향을 살피기 위해
  if (g_dot2_mib.lcm.test.pseudonym_cert.tv.down_resp_replace) {
    unzip_resp[0].len = g_dot2_mib.lcm.test.pseudonym_cert.tv.down_resp_size;
    memcpy(unzip_resp[0].octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.down_resp, unzip_resp[0].len);
  }
#endif

  /*
   * 수신된 익명인증서 다운로드응답문들을 처리한다 -> 발급된 익명인증서바이트열, 개인키 재구성값을 추출한다.
   */
  for (unsigned int j = 0; j < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; j++) {
    ret = dot2_ProcessCertDownloadResponse(kDot2CMHType_Pseudonym,
                                           unzip_resp[j].octs,
                                           unzip_resp[j].len,
                                           &cr_info,
                                           &(params->common.cert_enc_priv_key),
                                           &(params->cert_enc_exp_key),
                                           i_period,
                                           j,
                                           &(res->options.recon_privs[j]),
                                           &(res->options.certs[j]));
    if (ret < 0) {
      goto err;
    }
  }

  /*
   * 익명인증서세트에 대한 CMHF를 생성한다.
   */
  ret = dot2_MakeRotateCMHFforImplicitCert_2(kDot2CMHType_Pseudonym,
                                             i_period,
                                             kDot2CertJvalue_PseudonymMax,
                                             &(params->verify_exp_key),
                                             &(params->common.verify_priv_key),
                                             res->options.certs,
                                             res->options.recon_privs,
                                             &(cr_info.pca.cert_h),
                                             &(cr_info.pca.pub_key),
                                             &cmhf_name,
                                             &cmhf,
                                             &cmhf_size,
                                             res->options.priv_keys);
  if (ret < 0) {
    goto err;
  }

  /*
   * 결과를 반환한다.
   * 인증서바이트열, 개인키, 개인키재구성값 정보는 이미 반환변수에 저장되어 있다.
   */
  res->ret = kDot2Result_Success;
  res->common.cmhf_name = cmhf_name;
  res->common.cmhf = cmhf;
  res->common.cmhf_size = cmhf_size;
  if (params->return_options == true) {
    memcpy(res->options.dir_name, provisioning_req_h8_str, DOT2_H8_HEX_STR_LEN);
    for (unsigned int j = 0; j < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; j++) {
      dot2_SetPseudonymIdCertFileName(i_period, j, res->options.cert_filenames[j]);
      dot2_SetPseudonymIdPrivKeyFileName(i_period, j, res->options.priv_key_filenames[j]);
      dot2_SetPseudonymIdReconPrivFileName(i_period, j, res->options.recon_priv_filenames[j]);
    }
  }

  free(req);
  free(zip_resp.octs);
  dot2_ClearCertRequestInfo(&cr_info);
  for (unsigned int j = 0; j < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; j++) {
    if (unzip_resp[j].octs) {
      free(unzip_resp[j].octs);
    }
  }
  Log(kDot2LogLevel_Event, "Success to download pseudonym cert\n");
  return;

err:
  res->ret = ret;
  if (req) { free(req); }
  if (cmhf_name) { free(cmhf_name); }
  if (cmhf) { free(cmhf); }
  if (zip_resp.octs) { free(zip_resp.octs); }
  dot2_ClearCertRequestInfo(&cr_info);
  for (unsigned int j = 0; j < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; j++) {
    if (unzip_resp[j].octs) {
      free(unzip_resp[j].octs);
    }
  }
}
