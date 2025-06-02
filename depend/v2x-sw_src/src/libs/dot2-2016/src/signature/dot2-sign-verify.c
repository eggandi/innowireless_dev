/** 
 * @file
 * @brief 서명 검증 기능을 구현한 파일
 * @date 2020-04-05
 * @author gyun
 */

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-executer/openssl/dot2-openssl.h"
#include "spdu/dot2-spdu-inline.h"



/**
 * @brief SPDU에 대한 서명검증을 수행한다.
 * @param[in] work 작업정보
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_VerifySPDUSignature(struct Dot2SPDUProcessWork *work)
{
  Log(kDot2LogLevel_Event, "Verify SPDU signature\n");

  /*
   * 1) Openssl 기반 서명검증 지원 시:
   *  - 서명 검증을 수행한다.
   * 2) saf5400,craton2 기반 서명검증 지원 시:
   *  - H/W에 서명 검증을 요청한다.
   */
#if defined(_SIGN_VERIFY_OPENSSL_)
  return dot2_ossl_VerifySignature_2(&(work->data.tbs_h),
                                     &(work->data.signer_h),
                                     work->data.eck_signer_pub_key,
                                     &(work->data.sign));
#elif defined(_SIGN_VERIFY_SAF5400_)
  int ret = dot2_saf5400_RequestSPDUSignatureVerification(work);
  return ((ret < 0) ? ret : kDot2Result_SPDUSignVerificationRequested);
#elif defined(_SIGN_VERIFY_CRATON2_)
  int ret = dot2_craton2_RequestSPDUSignatureVerification(work);
  return ((ret < 0) ? ret : kDot2Result_SPDUSignVerificationRequested);
#else
#error "Signature verification method is not defined"
#endif
}
