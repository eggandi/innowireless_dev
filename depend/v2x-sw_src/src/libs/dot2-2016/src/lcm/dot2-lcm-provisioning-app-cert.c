/** 
  * @file 
  * @brief 응용인증서(Application certifiate) 발급요청 관련 구현
  * @date 2022-07-24 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
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
 * @brief RA에게 응용인증서 발급을 요청한다.
 * @param[in] params 응용인증서 발급요청 파라미터
 * @param[in] res 응용인증서 발급요청 결과가 저장될 구조체 포인터
 *
 * 응용인증서발급요청문을 생성하여 RA에 전송하고 응답문을 수신하여 결과를 반환한다.
 */
void INTERNAL dot2_RequestAppCertProvisioning(
  struct Dot2CertProvisioningRequestParams *params,
  struct Dot2AppCertProvisioningRequestResult *res)
{
  Log(kDot2LogLevel_Event, "Request app cert provisioning\n");

  uint8_t *req = NULL;
  Dot2SPDUSize req_size;
  struct Dot2HTTPSMessage ack = { NULL, 0 };

  Dot2Time32 current_time = dot2_GetCurrentTime32();
  Dot2Time32 start_time = (params->start_time) ? params->start_time : current_time;
  current_time = (params->current_time) ? params->current_time : current_time;

  /*
   * 인증서 발급요청을 위해 필요한 정보를 MIB에서 가져온다.
   */
  struct Dot2CertRequestInfo cr_info;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  int ret = dot2_GetCertRequestInfo(current_time, &cr_info);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if (ret < 0) {
    goto err;
  }
  if ((cr_info.https.acp_url == NULL) ||
      (cr_info.https.rca_tls_cert_file_path == NULL)) {
    Err("Fail to request app cert provisioning - no https connection info\n");
    ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    goto err;
  }

  /*
   * 서명용 임시 개인키/공개키를 생성한다.
   *  - 공개키는 인증서발급요청문에 수납되며, 개인키는 반환된다.
   */
  struct Dot2ECKeyPairOcts verify_key;
  ret = dot2_ossl_GenerateECKeyPairOcts(&verify_key);
  if (ret < 0) {
    goto err;
  }

  /*
   * 인증서복호화용 개인키/공개키를 생성한다.
   *  - 공개키는 인증서발급요청문에 수납되며, 개인키는 반환된다.
   */
  struct Dot2ECKeyPairOcts cert_encryption_key;
  ret = dot2_ossl_GenerateECKeyPairOcts(&cert_encryption_key);
  if (ret < 0) {
    goto err;
  }

#ifdef _UNIT_TEST_
  // 서명용 임시 개인키/공개키 및 인증서복호화용 개인키/공개키를 테스트벡터로 강제 교체한다 (이후 수신되는 응답문 테스트벡터를 정상적으로 처리하기 위해)
  memcpy(&verify_key, &(g_dot2_mib.lcm.test.app_cert.tv.verify_key), sizeof(struct Dot2ECKeyPairOcts));
  memcpy(&cert_encryption_key, &(g_dot2_mib.lcm.test.app_cert.tv.encryption_key), sizeof(struct Dot2ECKeyPairOcts));
#endif

  /*
   * 응용인증서 발급요청문을 생성한다.
   */
#if defined(_FFASN1C_)
  req = dot2_ffasn1c_ConstructSecuredCertProvisioningRequest(kDot2CMHType_Application,
                                                             current_time,
                                                             start_time,
                                                             &(verify_key.pub_key),
                                                             &(cert_encryption_key.pub_key),
                                                             NULL, // 미사용
                                                             NULL, // 미사용
                                                             &cr_info,
                                                             &ret);
  if (req == NULL) {
    goto err;
  }
#elif defined(_OBJASN1C_)
  req = dot2_objasn1c_ConstructSecuredCertProvisioningRequest(kDot2CMHType_Application,
                                                              current_time,
                                                              start_time,
                                                              &(verify_key.pub_key),
                                                              &(cert_encryption_key.pub_key),
                                                              NULL, // 미사용
                                                              NULL, // 미사용
                                                              &cr_info,
                                                              &ret);
  if (req == NULL) {
    goto err;
  }
#else
#error "3rd party asn.1 library is not defined"
#endif
  req_size = (Dot2SPDUSize)ret;

  /*
   * 응용인증서 발급요청문에 대한 H8를 계산한다.
   */
  struct Dot2SHA256 req_h;
  SHA256(req, req_size, req_h.octs);
  uint8_t *req_h8 = DOT2_GET_SHA256_H8(req_h.octs);

#ifdef _UNIT_TEST_
  // 발급요청문 H8을 테스트벡터 정보로 강제 교체한다 (테스트벡터 발급응답문 내 Req_H8 값과 맞추기 위해)
  memcpy(req_h8, g_dot2_mib.lcm.test.app_cert.tv.provisioning_req_h8, 8);
#endif

  /*
   * RA에게 응용인증서발급요청문을 전송하고, 응용인증서발급응답문을 수신한다.
   */
  ret = dot2_HTTPS_POST(cr_info.https.acp_url, cr_info.https.rca_tls_cert_file_path, req, req_size, &ack);
  if (ret < 0) {
    goto err;
  }

  /*
   * 수신된 응용인증서발급응답문을 처리한다.
   */
  Dot2Time32 cert_dl_time;
  char *cert_dl_url;
  Dot2CMHType cert_type = kDot2CMHType_Application;
  ret = dot2_ProcessCertProvisioningAck(cert_type, ack.octs, ack.len, req_h8, &cr_info, &cert_dl_time, &cert_dl_url);
  if (ret < 0) {
    goto err;
  }

  /*
   * 결과를 반환한다.
   */
  res->ret = kDot2Result_Success;
  memcpy(&(res->common.req_h8), req_h8, 8);
  memcpy(&(res->common.verify_priv_key), &(verify_key.priv_key), sizeof(struct Dot2ECPrivateKey));
  memcpy(&(res->common.cert_enc_priv_key), &(cert_encryption_key.priv_key), sizeof(struct Dot2ECPrivateKey));
  res->common.cert_dl_url = cert_dl_url;
  res->common.cert_dl_time = cert_dl_time;
  res->common.current_time = dot2_GetCurrentTime32();
  res->common.remained_cert_dl_time = (int)dot2_ConvertTime32ToSystemTimeSeconds(cert_dl_time) - (int)dot2_GetCurrentSystemTimeInSeconds();
  if (params->return_options == true) {
    res->options.req = req;
    res->options.req_size = req_size;
    res->options.ack = ack.octs;
    res->options.ack_size = ack.len;
  } else {
    free(req);
    free(ack.octs);
  }
  dot2_ClearCertRequestInfo(&cr_info);
  Log(kDot2LogLevel_Event, "Success to request app cert provisioning\n");
  return;

err:
  res->ret = ret;
  if (req) { free(req); }
  if (ack.octs) { free(ack.octs); }
  dot2_ClearCertRequestInfo(&cr_info);
}
