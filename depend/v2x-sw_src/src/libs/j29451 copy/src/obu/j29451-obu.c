/** 
 * @file
 * @brief OBU 관련 기능을 구현한 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>
 
// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"


/**
 * @brief OBU 정보를 초기화한다.
 * @param[in] obu OBU 정보
 * @retval 0: 성공
 * @retval 음수(-J29451ResultCode): 실패
 */
int INTERNAL j29451_InitOBUInfo(struct J29451OBUInfo *obu)
{
  Log(kJ29451LogLevel_Event, "Initialize OBU info\n");
  memset(obu, 0, sizeof(struct J29451OBUInfo));
  obu->hard_braking_decision = true;
  return j29451_InitGNSSInfo(&(obu->gnss));
}


/**
 * @brief OBU 정보를 해제한다.
 * @param[in] obu OBU 정보
 */
void INTERNAL j29451_ReleaseOBUInfo(struct J29451OBUInfo *obu)
{
  Log(kJ29451LogLevel_Event, "Release OBU info\n");
  j29451_ReleaseGNSSInfo(&(obu->gnss));
}
