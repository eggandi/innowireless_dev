/** 
  * @file 
  * @brief 익명인증서(Pseudonym certificate) 메시지 생성/처리 관련 구현
  * @date 2022-08-09 
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
 * @brief 익명인증서 발급요청문 내 EeRaPseudonymCertProvisioningRequest 필드를 채운다.
 * @param[in] current_time 현재시각
 * @param[in] start_time 익명인증서 유효기간 시작시점
 * @param[in] verify_pub_key 서명용 caterpillar 공개키
 * @param[in] cert_enc_pub_key 발급인증서 암호화용 공개키
 * @param[in] verify_exp_key 서명용 확장함수 키
 * @param[in] cert_enc_exp_key 인증서암복호화용 확장함수 키
 * @param[out] asn1_req 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_FillEeRaPseudonymCertProvisioningRequest(
  Dot2Time32 current_time,
  Dot2Time32 start_time,
  const struct Dot2ECPublicKey *verify_pub_key,
  const struct Dot2ECPublicKey *cert_enc_pub_key,
  const struct Dot2AESKey *verify_exp_key,
  const struct Dot2AESKey *cert_enc_exp_key,
  dot2EeRaPseudonymCertProvisioningRequest *asn1_req)
{
  Log(kDot2LogLevel_Event, "Fill EeRaPseudonymCertProvisioningRequest\n");

  asn1_req->version = KDot2ScmsPDUVersion_SCMS;

  /*
   * 서명용 Caterpillar 공개키 및 확장함수키를 채운다.
   */
  int ret = dot2_ffasn1c_FillUnsignedButterflyParams(verify_pub_key, verify_exp_key, &(asn1_req->verify_key_info));
  if (ret < 0) {
    return ret;
  }

  /*
   * 옵션정보인 암호화용 공개키는 채우지 않는다. (익명인증서에 포함될 암호화용 공개키)
   *  - V2X 보안인증체계 세부 기술규격(KISA) v1.1에 따라, 현재 익명인증서 내에는 암호화용 공개키가 포함되지 않는다.
   */

  /*
   * 인증서암호화용 caterpillar 공개키 및 확장함수키를 채운다. (RA가 인증서발급할 때 메시지를 암호화할 공개키)
   */
  ret = dot2_ffasn1c_FillUnsignedButterflyParams(cert_enc_pub_key, cert_enc_exp_key, &(asn1_req->resp_enc_key_info));
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
