/**
 * @file
 * @brief 등록인증서 발급응답문 관련 구현
 * @date 2022-05-05
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c.h"


/**
 * @brief 등록인증서 발급응답문을 파싱한다.
 * @param[in] ec_resp 파싱할 등록인증서 발급응답문 바이트열
 * @param[in] ec_resp_size ec_resp의 길이
 * @param[out] ec_req_h8 등록인증서 발급응답문 내에 포함된 requestHash값이 반환될 버퍼(8바이트 길이를 가진다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseECResponse(const uint8_t *ec_resp, size_t ec_resp_size, uint8_t *ec_req_h8)
{
  Log(kDot2LogLevel_Event, "Parse ECResponse\n");
  int ret;
  dot2SignedEeEnrollmentCertResponse *asn1_ec_resp = NULL;
  dot2ScopedEeEnrollmentCertResponse *asn1_scoped_ecr = NULL;

  /*
   * 등록인증서 발급응답문(ECResponse)을 디코딩한다.
   */
  ASN1Error asn1_err;
  asn1_ssize_t dec_size = asn1_oer_decode((void **)&asn1_ec_resp,
                                          asn1_type_dot2SignedEeEnrollmentCertResponse,
                                          ec_resp,
                                          ec_resp_size,
                                          &asn1_err);
  if (dec_size < 0) {
    return -kDot2Result_ASN1_DecodeECResponse;
  }

  /*
   * 등록인증서 발급응답문의 형식이 유효한지 확인한다.
   */
  if ((asn1_ec_resp->content.choice != dot2Ieee1609Dot2Content_signedData) ||
      (asn1_ec_resp->content.u.signedData.tbsData.payload.data == NULL) ||
      (asn1_ec_resp->content.u.signedData.tbsData.payload.data->content.choice != dot2Ieee1609Dot2Content_unsecuredData) ||
      (asn1_ec_resp->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.buf == NULL)) {
    ret = -kDot2Result_LCM_InvalidECResponseContent;
    goto out;
  }

  /*
   * 등록인증서 발급응답문 내 ScopedEeEnrollmentCertResponse를 디코딩한다.
   */
  uint8_t *scoped_ecr = asn1_ec_resp->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.buf;
  size_t scoped_ecr_size = asn1_ec_resp->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.len;
  dec_size = asn1_oer_decode((void **)&asn1_scoped_ecr,
                             asn1_type_dot2ScopedEeEnrollmentCertResponse,
                             scoped_ecr,
                             scoped_ecr_size,
                             &asn1_err);
  if (dec_size < 0) {
    ret = -kDot2Result_ASN1_DecodeScopedEeEnrollmentCertResponse;
    goto out;
  }

  /*
   * ScopedEeEnrollmentCertResponse에서 requestHash값과 개인키재구성값을 반환한다.
   */
  ret = -kDot2Result_LCM_InvalidECResponseContent;
  if ((asn1_scoped_ecr->content.choice == dot2ScmsPDU_1_eca_ee) &&
      (asn1_scoped_ecr->content.u.eca_ee.choice == dot2EcaEndEntityInterfacePDU_ecaEeCertResponse) &&
      (asn1_scoped_ecr->content.u.eca_ee.u.ecaEeCertResponse.requestHash.buf) &&
      (asn1_scoped_ecr->content.u.eca_ee.u.ecaEeCertResponse.requestHash.len == 8) &&
      (asn1_scoped_ecr->content.u.eca_ee.u.ecaEeCertResponse.privKeyReconstruction.buf) &&
      (asn1_scoped_ecr->content.u.eca_ee.u.ecaEeCertResponse.privKeyReconstruction.len == DOT2_EC_256_KEY_LEN)) {
    memcpy(ec_req_h8, asn1_scoped_ecr->content.u.eca_ee.u.ecaEeCertResponse.requestHash.buf, 8);
    ret = kDot2Result_Success;
  }

out:
  if (asn1_scoped_ecr) { asn1_free_value(asn1_type_dot2ScopedEeEnrollmentCertResponse, asn1_scoped_ecr); }
  if (asn1_ec_resp) { asn1_free_value(asn1_type_dot2SignedEeEnrollmentCertResponse, asn1_ec_resp); }
  return ret;
}
