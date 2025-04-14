/** 
 * @file
 * @brief 유형 정의 헤더
 * @date 2022-09-17
 * @author gyun
 */


#ifndef V2X_SW_BSMD_TYPES_H
#define V2X_SW_BSMD_TYPES_H


/**
 * @brief 디버그 메시지 출력 레벨
 */
enum eBSMDLogLevel
{
  kBSMDLogLevel_None = 0,
  kBSMDLogLevel_Err = 1,
  kBSMDLogLevel_Event = 2,
  kBSMDLogLevel_DetailedEvent = 3,
  kBSMDLogLevel_PktDump = 4,
  kBSMDLogLevel_All,
};
typedef unsigned int BSMDLogLevel; ///< @ref eBSMDLogLevel

#endif // V2X_SW_BSMD_TYPES_H
