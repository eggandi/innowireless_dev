/** 
  * @file 
  * @brief 응용인증서(Application certificate) 메시지 생성/처리 관련 구현
  * @date 2022-07-24 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#include "asn1/ffasn1c/dot2-ffasn1c-inline.h"
#include "lcm/dot2-lcm.h"


/**
 * @brief 응용인증서 발급요청문 내 EeRaAppCertProvisioningRequest 필드를 채운다.
 * @param[in] current_time 현재시각
 * @param[in] start_time 응용인증서 유효기간 시작시점
 * @param[in] verify_pub_key 서명용 임시 공개키
 * @param[in] cert_enc_pub_key 발급인증서 암호화용 공개키
 * @param[out] asn1_req 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_FillEeRaAppCertProvisioningRequest(
  Dot2Time32 current_time,
  Dot2Time32 start_time,
  const struct Dot2ECPublicKey *verify_pub_key,
  const struct Dot2ECPublicKey *cert_enc_pub_key,
  dot2EeRaAppCertProvisioningRequest *asn1_req)
{
  Log(kDot2LogLevel_Event, "Fill EeRaAppCertProvisioningRequest\n");

  asn1_req->version = KDot2ScmsPDUVersion_SCMS;

  /*
   * 서명검증용 공개키를 압축형식으로 채운다. (응용인증서에 포함될 서명검증용 공개키)
   */
  int ret = dot2_ffasn1c_FillPublicVerificationKey(verify_pub_key, &(asn1_req->verify_key));
  if (ret < 0) {
    return ret;
  }

  /*
   * 옵션정보인 암호화용 공개키는 채우지 않는다. (응용인증서에 포함될 암호화용 공개키)
   *  - V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, 현재 응용인증서 내에는 암호화용 공개키가 포함되지 않는다.
   */

  /*
   * 인증서암호화용 공개키를 압축형식으로 채운다. (RA가 인증서발급할 때 메시지를 암호화할 공개키)
   */
  ret = dot2_ffasn1c_FillPublicEncryptionKey(cert_enc_pub_key, &(asn1_req->response_encryption_key));
  if (ret < 0) {
    return ret;
  }

  /*
   * 공통정보(현재시각 및 요청하는 인증서 유효기간 시작시각)를 채운다.
   */
  asn1_req->common.current_time = current_time;
  asn1_req->common.requested_start_time = start_time;

  return kDot2Result_Success;
}
