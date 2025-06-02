/** 
  * @file 
  * @brief 인증서 발급 관련 구현
  * @date 2022-08-14 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

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
 * @brief 인증서 발급응답문을 처리한다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] ack 처리할 인증서 발급응답문 바이트열
 * @param[in] ack_size 인증서 발급응답문 바이트열의 길이
 * @param[in] req_h8 인증서 발급요청문에 대한 H8 (응답문 내 requestHash 값 비교를 위해 사용된다)
 * @param[out] cert_dl_time 인증서 발급응답문 내에 포함된 다운로드 가능시간이 저장될 변수 포인터
 * @param[out] cert_dl_url 인증서 발급응답문 내에 포함된 다운로드 URL이 저장될 변수 포인터 (사용 후 free() 되어야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ProcessCertProvisioningAck(
  Dot2CMHType cert_type,
  const uint8_t *ack,
  Dot2SPDUSize ack_size,
  const uint8_t *req_h8,
  struct Dot2CertRequestInfo *cr_info,
  Dot2Time32 *cert_dl_time,
  char **cert_dl_url)
{
  Log(kDot2LogLevel_Event, "Process cert provisioning ack\n");

  if (!ack ||
      (dot2_CheckSPDUSize(ack_size) == false)) {
    return -kDot2Result_LCM_InvalidCertProvisioningAck;
  }

  /*
   * 인증서 발급응답문에서 정보를 파싱한다.
   * - 발급응답문 내에는 requestHash, 다운로드가능시간, 다운로드 URL이 포함되어 있다.
   */
  uint8_t req_h8_in_resp[8];
  struct Dot2Signature sign;
  uint8_t *tbs = NULL;
  Dot2SPDUSize tbs_size;
#if defined(_FFASN1C_)
  int ret = dot2_ffasn1c_ParseSignedCertProvisioningAck(cert_type,
                                                        ack,
                                                        ack_size,
                                                        req_h8_in_resp,
                                                        cert_dl_time,
                                                        cert_dl_url,
                                                        &tbs,
                                                        &tbs_size,
                                                        &sign);
#elif defined(_OBJASN1C_)
  int ret = dot2_objasn1c_ParseSignedCertProvisioningAck(cert_type,
                                                         ack,
                                                         ack_size,
                                                         req_h8_in_resp,
                                                         cert_dl_time,
                                                         cert_dl_url,
                                                         &tbs,
                                                         &tbs_size,
                                                         &sign);
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (ret < 0) {
    return ret;
  }

  /*
   * 인증서 발급응답문 내 requestHash값이 H8(요청문)과 동일한지 확인한다.
   */
  if (memcmp(req_h8, req_h8_in_resp, 8) != 0) {
    Err("Fail to process cert provisioning ack - different req H\n");
    ret = -kDot2Result_LCM_DifferentCertProvisioningAckRequestHash;
    goto err;
  }

  /*
   * 인증서 발급응답문 내 서명을 검증한다.
   */
  ret = dot2_ossl_VerifySignature_1(tbs, tbs_size, &(cr_info->ra.cert_h), cr_info->ra.eck_verify_pub_key, &sign);
  if (ret < 0) {
    goto err;
  }

  Log(kDot2LogLevel_Event, "Success to process cert provisioning ack\n");
  if (tbs) { free(tbs); }
  return kDot2Result_Success;

err:
  if (tbs) { free(tbs); }
  free(*cert_dl_url);
  *cert_dl_url = NULL;
  return ret;
}
