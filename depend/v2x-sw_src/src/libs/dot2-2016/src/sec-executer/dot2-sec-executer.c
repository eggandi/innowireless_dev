/** 
  * @file 
  * @brief 보안연산실행자 관련 기능 구현
  * @date 2022-07-02 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief 보안연산실행자를 초기화한다.
 * @param[in] interval 서명파라미터 계산주기
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_InitSecExecuter(Dot2SigningParamsPrecomputeInterval interval)
{
  Log(kDot2LogLevel_Event, "Initialize security executuer\n");

  /*
   * Openssl 기반 보안연산실행자를 초기화한다.
   * (Openssl은 항상 사용된다)
   */
  int ret = dot2_ossl_InitSecExecuter(interval);

  /*
   * SPDU 서명검증연산을 위해 사용되는 H/W 기반 보안연산실행자 기능을 초기화한다.
   */
#if defined(_SIGN_VERIFY_SAF5400_)
  if (ret == kDot2Result_Success) {
    ret = dot2_saf5400_InitSecExecuter(&(g_dot2_mib.sec_executer.saf5400));
  }
#elif defined(_SIGN_VERIFY_CRATON2_)
  if (ret == kDot2Result_Success) {
    ret = dot2_craton2_InitSecExecuter(&(g_dot2_mib.craton2));
  }
#endif

  return ret;
}


/**
 * @brief 보안연산실행자를 해제한다.
 */
void INTERNAL dot2_ReleaseSecExecuter(void)
{
  Log(kDot2LogLevel_Event, "Release security executer\n");

  /*
   * Openssl 기반 보안연산실행자를 제거한다.
   */
  dot2_ossl_ReleaseSecExecuter();

  /*
   * SPDU 서명검증연산을 위해 사용되는 H/W 기반 보안연산실행자 기능을 해제한다.
   */
#if defined(_SIGN_VERIFY_SAF5400_)
  dot2_saf5400_ReleaseSecExecuter();
#elif defined(_SIGN_VERIFY_CRATON2_)
  dot2_craton2_ReleaseSecExecuter(&(g_dot2_mib.craton2));
#endif
}

