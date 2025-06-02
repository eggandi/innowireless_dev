/**
 * @file
 * @brief libdot3 Open API 중 기본 API를 구현한 파일
 * @date 2019-06-06
 * @author gyun
 */

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief dot3 라이브러리를 초기화한다(상세 내용 API 매뉴얼 참조).
 * @param[in] log_level 로그메시지 출력레벨
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_Init(Dot3LogLevel log_level)
{
  return dot3_InitDot3(log_level);
}


/**
 * @brief dot3 라이브러리를 해제한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot3_Release(void)
{
  dot3_ReleaseDot3();
}


/**
 * @brief API 결과값에 대한 설명문자열을 반환한다(상세 내용 API 매뉴얼 참조).
 * @param[in] ret API 결과값
 * @return 결과코드에 대한 설명문자열
 */
const char OPEN_API * Dot3_GetResultStr(int ret)
{
  int rc = ret * -1;
  if ((rc >= kDot3Result_Success) && (rc < kDot3Result_Count)) {
    return g_dot3_rc_str[rc];
  }
  return "No result string - You may specify invalid return value";
}
