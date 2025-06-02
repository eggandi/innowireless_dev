/** 
 * @file
 * @brief Security profile 기능 정의 헤더 파일
 * @date 2020-05-15
 * @author gyun
 */


#ifndef V2X_SW_DOT2_SEC_PROFILE_H
#define V2X_SW_DOT2_SEC_PROFILE_H

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "dot2-sec-profile-replay.h"


/**
 * @brief "Security profile 테이블" 내에 저장되는 "Security profile 엔트리"들의 개수
 */
enum eDot2SecProfileEntryNum
{
  kDot2SecProfileEntryNum_Min = 0,
  kDot2SecProfileEntryNum_Max = 100, ///< 최대값(자체 정의)- 100개까지의 PSID 사용 가능
};
typedef unsigned int Dot2SecProfileEntryNum; ///< @ref eDot2SecProfileEntryNum


/**
 * @brief "Security profile 엔트리" 형식
 *
 * 각 PSID에 대한 security profile이 저장되며, 내부적으로 추적되는 정보(internal)가 저장된다.
 */
struct Dot2SecProfileEntry
{
  struct Dot2SecProfile profile; ///< Security profile 정보
  Dot2Time64 last_cert_sign_time; ///< 가장 최근에 인증서로 서명된 시각
                                  ///< (CMH가 변경되거나, 어플리케이션이 다이제스트로 서명을 직접 요청하면 0으로 초기화된다)
  struct Dot2SecProfileReplayCheckList replay_check_list; ///< 수신 SPDU replay 체크 리스트
  TAILQ_ENTRY(Dot2SecProfileEntry) entries; ///< 엔트리간 연결정보
};
TAILQ_HEAD(Dot2SecProfileEntryHead, Dot2SecProfileEntry);


/**
 * @brief "Security profile 테이블" 형식
 *
 * PSID 별 Security profile 정보들이 저장된다.
 */
struct Dot2SecProfileTable
{
  struct Dot2SecProfileEntryHead head; ///< "Security profile 엔트리"들에 대한 접근정보
  Dot2SecProfileEntryNum entry_num; ///< 엔트리 개수
  Dot2SecProfileEntryNum max_entry_num; ///< 저장 가능한 최대 개수
};


#endif //V2X_SW_DOT2_SEC_PROFILE_H
