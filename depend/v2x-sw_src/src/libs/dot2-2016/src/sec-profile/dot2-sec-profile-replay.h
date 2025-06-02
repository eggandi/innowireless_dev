/** 
  * @file 
  * @brief 
  * @date 2021-07-30 
  * @author gyun 
  */


#ifndef V2X_SW_DOT2_SEC_PROFILE_REPLAY_H
#define V2X_SW_DOT2_SEC_PROFILE_REPLAY_H


// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"


/**
 * @brief Replay 체크리스트 엔트리 개수
 */
enum eDot2SecProfileReplayCheckEntryNum
{
  kDot2SecProfileReplayCheckEntryNum_Min = 0,
  kDot2SecProfileReplayCheckEntryNum_Max = 10000, ///< 최대값 임의로 지정
};
typedef unsigned int Dot2SecProfileReplayCheckEntryNum; ///< @ref eDot2SecProfileReplayCheckEntryNum


/**
 * @brief Replay 체크를 위한 정보 엔트리
 *
 * SPDU의 중복 여부를 판단하기 위해 SPDU의 생성시각과 서명이 사용된다.
 * 엄격하게 할 경우 SPDU 전체를 비교해야 하지만, 성능의 감소가 발생할 수 있다.
 * 따라서 중복 SPDU가 아닐 경우에 항상 다를 거라고 생각되는 정보만을 비교하는 것으로 구현한다.
 * 생성시각은 마이크로초 단위이므로 항상 다를 것이다. 다만, 생성시각은 option 필드이므로 존재하지 않을 경우 비교하는데 사용할 수 없다.
 * 서명은 랜덤값을 기반으로 생성되므로 항상 다를 것이다. (서로 다른 SPDU에 대해 동일한 서명 R,s가 생성될 확률은 거의 없다)
 */
struct Dot2SecProfileReplayCheckEntry
{
  Dot2Time64 entry_gen_time; ///< 엔트리 생성시각.
  Dot2Time64 spdu_gen_time; ///< SPDU의 생성시각. 존재하지 않는 경우 0으로 설정되며 중복체크를 위한 비교대상에서 제외된다.
  struct Dot2Signature spdu_sign; ///< SPDU의 서명.
  TAILQ_ENTRY(Dot2SecProfileReplayCheckEntry) entries; ///< 엔트리간 연결정보
};
TAILQ_HEAD(Dot2SecProfileReplayCheckEntryHead, Dot2SecProfileReplayCheckEntry);


/**
 * @brief Replay 체크를 위한 정보 리스트
 *
 * 실제 환경에서 Replay SPDU는 많지 않을 것으로 예상되며(Replay 메시지인 WSA는 애초에 Replay 체크를 하지 않음),
 * 따라서 탐색시간이 그리 길지 않을 것으로 생각되어 계층 구조를 갖지 않는 일차 리스트로 구현함.
 */
struct Dot2SecProfileReplayCheckList
{
  Dot2SecProfileReplayCheckEntryNum entry_num; ///< 엔트리 개수
  struct Dot2SecProfileReplayCheckEntryHead head; ///< 엔트리들에 대한 접근 정보(=리스트)
};


#endif //V2X_SW_DOT2_SEC_PROFILE_REPLAY_H
