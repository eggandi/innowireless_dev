/**
 * @file
 * @brief dot2 라이브러리의 기본 API들을 구현한 파일
 * @date 2020-02-18
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/**
 * @brief dot2 라이브러리를 초기화한다(상세 내용 API 매뉴얼 참조).
 * @param[in] log_level 로그메시지 출력 레벨
 * @param[in] interval 서명파라미터 계산 주기
 * @param[in] rng_dev 난수생성기 이름(예: /dev/random, /dev/urandom).
 *                    NULL을 전달할 경우 난수생성기 대신 소프트웨어 random() 함수를 통해 난수를 생성한다.
 * @param[in] leap_secs 2004-01-01 이후로 적용된 윤초 값
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int OPEN_API Dot2_Init(
  Dot2LogLevel log_level,
  Dot2SigningParamsPrecomputeInterval interval,
  const char *rng_dev,
  Dot2LeapSeconds leap_secs)
{
  // 로그메시지 출력 레벨이 아직 설정되지 않았으므로, 파라미터 유효성 체크는 아래 함수 내에서 수행한다.

  return dot2_InitDot2(log_level, interval, rng_dev, leap_secs);
}


/**
 * @brief dot2 라이브러리를 종료한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot2_Release(void)
{
  dot2_ReleaseDot2();
}


/**
 * @brief 초단위 시스템 시간값을 Time32 값으로 변환한다(상세 내용 API 매뉴얼 참조).
 * @param[in] sec 변환할 시스템시간(초 단위)
 * @return 변환된 Time32 값 (2004년 1월 1일보다 과거일 경우 0)
 *
 * 시스템 시간: 1970-01-01 0시 이후부터의 초 값 (UTC)
 * Time32: 2004-01-01 0시 이후부터의 초값 (TAI)
 */
Dot2Time32 OPEN_API Dot2_ConvertSystemTimeToTime32(time_t sec)
{
  return dot2_ConvertSystemTimeToTime32(sec);
}
