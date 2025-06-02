/** 
 * @file
 * @brief dot2 라이브러리 기본 기능을 구현한 파일
 * @date 2020-04-02
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/*
 * dot2 라이브러리 관리정보
 */
struct Dot2MIB g_dot2_mib;


/**
 * @brief dot2 라이브러리를 초기화한다.
 * @param[in] log_level 로그메시지 출력 레벨
 * @param[in] interval 서명파라미터 계산 주기
 * @param[in] rng_dev 난수생성기 이름(예: /dev/random, /dev/urandom).
 *                    NULL을 전달할 경우 난수생성기 대신 소프트웨어 random() 함수를 통해 난수를 생성한다.
 * @param[in] leap_secs 2004-01-01 이후로 적용된 윤초 값
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_InitDot2(
  Dot2LogLevel log_level,
  Dot2SigningParamsPrecomputeInterval interval,
  const char *rng_dev,
  Dot2LeapSeconds leap_secs)
{
  /*
   * 로그 레벨을 설정한다.
   */
  g_dot2_log = (log_level > kDot2LogLevel_Max) ? kDot2LogLevel_Max : log_level;
  Log(kDot2LogLevel_Init, "Initialize dot2 library - log level: %u\n", log_level);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot2_CheckSigningParamsPrecomputeInterval(interval) == false) {
    Err("Fail to initialize dot2 library - invalid sign params precompute interval: %umsec\n", interval);
    return -kDot2Result_InvalidInterval;
  }

  memset(&g_dot2_mib, 0, sizeof(g_dot2_mib));
  pthread_mutex_init(&(g_dot2_mib.mtx), NULL);

  /*
   * 윤초를 저장한다.
   */
  g_dot2_mib.leap_secs = leap_secs;

  /*
   * 난수생성기 정보를 설정한다.
   */
  int ret = dot2_SetRandomNumberGenerator(rng_dev);
  if (ret < 0) {
    return ret;
  }

  /*
   * CA인증서정보 테이블을 초기화한다.
   */
  dot2_InitSCCCertInfoTable();

  /*
   * 타 장치(EE) 인증서캐시 테이블을 초기화한다.
   */
  dot2_InitEECertCacheTable();

  /*
   * CMH 테이블을 초기화한다.
   */
  dot2_InitCMHTable();

  /*
   * Security profile 테이블을 초기화한다.
   */
  dot2_InitSecProfileTable();

#ifdef _SUPPORT_SCMS_
  /*
   * CRL 테이블을 초기화한다.
   */
  dot2_InitCRLTable();
#endif

  /*
   * 보안연산실행자 기능을 초기화한다.
   */
  ret = dot2_InitSecExecuter(interval);
  if (ret < 0) {
    return ret;
  }

  /*
   * SPDU 처리 기능을 초기화한다.
   */
  ret = dot2_InitSPDUProcessFunction(&(g_dot2_mib.spdu_process));
  if (ret < 0) {
    return ret;
  }

  Log(kDot2LogLevel_Init, "Success to initialize dot2 library\n");
  return kDot2Result_Success;
}


/**
 * @brief dot2 라이브러리를 해제한다.
 */
void INTERNAL dot2_ReleaseDot2(void)
{
  Log(kDot2LogLevel_Event, "Release dot2 library\n");

  /*
   * SPDU 처리 기능을 종료한다.
   */
  dot2_ReleaseSPDUProcessFunction(&(g_dot2_mib.spdu_process));

  /*
   * CA인증서정보 테이블을 해제한다.
   */
  dot2_ReleaseSCCCertInfoTable();

  /*
   * 타 장치(EE) 인증서캐시 테이블을 해제한다.
   */
  dot2_ReleaseEECertCacheTable();

  /*
   * CMH 테이블을 해제한다.
   */
  dot2_ReleaseCMHTable();

  /*
   * Security profile 테이블을 해제한다.
   */
  dot2_ReleaseSecProfileTable();

#ifdef _SUPPORT_SCMS_
  /*
   * CRL 테이블을 초기화한다.
   */
  dot2_ReleaseCRLTable();
#endif

  /*
   * 보안연산실행자 기능을 해제한다.
   */
  dot2_ReleaseSecExecuter();
}
