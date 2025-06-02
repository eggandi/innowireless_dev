/** 
  * @file 
  * @brief 
  * @date 2021-07-30 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-sec-profile-replay.h"


/**
 * @brief Replay 체크 리스트를 초기화한다.
 * @param[in] list Replay 체크 리스트
 */
void INTERNAL dot2_InitSecProfileReplayCheckList(struct Dot2SecProfileReplayCheckList *list)
{
  Log(kDot2LogLevel_Event, "Initialize replay check list\n");
  list->entry_num = 0;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief Replay 체크 엔트리를 리스트 내에서 제거한다.
 * @param[in] list Replay 체크 리스트
 * @param[in] entry Replay 체크 엔트리
 */
static inline void dot2_RemoveSecProfileReplayCheckEntry(
  struct Dot2SecProfileReplayCheckList *list,
  struct Dot2SecProfileReplayCheckEntry *entry)
{
  TAILQ_REMOVE(&(list->head), entry, entries);
  free(entry);
  list->entry_num--;
}


/**
 * @brief Replay 체크 리스트를 비운다.
 * @param[in] list Replay 체크 리스트
 */
void INTERNAL dot2_FlushSecProfileReplayCheckList(struct Dot2SecProfileReplayCheckList *list)
{
  Log(kDot2LogLevel_Event, "Flush replay check list\n");
  struct Dot2SecProfileReplayCheckEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    dot2_RemoveSecProfileReplayCheckEntry(list, entry);
  }
  list->entry_num = 0;
}


/**
 * @brief Replay 체크 엔트리를 할당하고 정보를 저장한다.
 * @param[in] spdu_rx_time SPDU 수신 시각
 * @param[in] spdu_gen_time SPDU 생성 시각
 * @param[in] spdu_sign SPDU 서명
 * @return 할당된 엔트리 포인터
 * @retval NULL: 실패
 */
static inline struct Dot2SecProfileReplayCheckEntry * dot2_AllocateSecProfileReplayCheckEntry(
  Dot2Time64 spdu_rx_time,
  Dot2Time64 spdu_gen_time,
  struct Dot2Signature *spdu_sign)
{
  struct Dot2SecProfileReplayCheckEntry *entry;
  entry = (struct Dot2SecProfileReplayCheckEntry *)calloc(1, sizeof(struct Dot2SecProfileReplayCheckEntry));
  if (entry) {
    entry->entry_gen_time = spdu_rx_time; // SPDU 수신시각은 엔트리 생성시각으로 저장된다.
    entry->spdu_gen_time = spdu_gen_time;
    memcpy(&(entry->spdu_sign), spdu_sign, sizeof(struct Dot2Signature));
  }
  return entry;
}


/**
 * @brief Replay 체크 리스트 내에서 가장 오래된 엔트리를 제거한다.
 * @param[in] list Replay 체크 리스트
 */
static inline void dot2_RemoveOldestSecProfileReplayCheckEntry(struct Dot2SecProfileReplayCheckList *list)
{
  struct Dot2SecProfileReplayCheckEntry *oldest = TAILQ_FIRST(&(list->head));
  if (oldest) {
    dot2_RemoveSecProfileReplayCheckEntry(list, oldest);
  }
}


/**
 * @brief Replay 체크엔트리를 리스트에 추가한다.
 * @param[in] list Replay 체크리스트
 * @param[in] entry Replay 체크엔트리
 */
static inline void dot2_PushSecProfileReplayCheckEntry(
  struct Dot2SecProfileReplayCheckList *list,
  struct Dot2SecProfileReplayCheckEntry *entry)
{
  /*
   * 리스트가 가득 차 있으면 가장 오래된 엔트리를 삭제한다.
   */
  if (list->entry_num >= kDot2SecProfileReplayCheckEntryNum_Max) {
    dot2_RemoveOldestSecProfileReplayCheckEntry(list);
  }

  /*
   * 리스트의 마지막에 삽입한다.
   */
  TAILQ_INSERT_TAIL(&(list->head), entry, entries);
  list->entry_num++;
}


/**
 * @brief Replay 체크 리스트 내에 엔트리를 추가한다.
 * @param[in] list Replay 체크 리스트
 * @param[in] spdu_rx_time SPDU 수신 시각
 * @param[in] spdu_gen_time SPDU 생성 시각
 * @param[in] spdu_sign SPDU 서명
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddSecProfileReplayCheckEntry(
  struct Dot2SecProfileReplayCheckList *list,
  Dot2Time64 spdu_rx_time,
  Dot2Time64 spdu_gen_time,
  struct Dot2Signature *spdu_sign)
{
  Log(kDot2LogLevel_Event, "Add replay check entry - gen time: %"PRIu64"\n", spdu_rx_time);

  /*
   * 엔트리를 할당하여 정보 저장 후 리스트에 추가한다.
   */
  int ret = -kDot2Result_NoMemory;
  struct Dot2SecProfileReplayCheckEntry *entry = dot2_AllocateSecProfileReplayCheckEntry(spdu_rx_time,
                                                                                         spdu_gen_time,
                                                                                         spdu_sign);
  if (entry) {
    dot2_PushSecProfileReplayCheckEntry(list, entry);
    ret = kDot2Result_Success;
  }
  return ret;
}


/**
 * @brief 특정 replay 체크 엔트리에 저장된 정보와 특정 SPDU 정보 집합이 동일한지 확인한다.
 * @param[in] entry Replay 체크 리스트 엔트리
 * @param[in] spdu_gen_time SPDU 생성 시각
 * @param[in] spdu_sign SPDU 서명
 * @return 동일한지 여부
 */
bool INTERNAL dot2_CheckIdenticalSecProfileReplayCheckEntry(
  struct Dot2SecProfileReplayCheckEntry *entry,
  Dot2Time64 spdu_gen_time,
  struct Dot2Signature *spdu_sign)
{
  Log(kDot2LogLevel_Event, "Check identical replay check entry\n");

  // 서명 s 값이 다르면 동일한 SPDU가 아니다. 빠르게 진행하기 위해 일단 2바이트만 비교한다.
  // 동일하지 않은 SPDU의 서명 s 값의 2바이트 값이 우연히 같을 경우, 아래 전체 비교문에서 다시 체크된다.
  if ((entry->spdu_sign.s[0] != spdu_sign->s[0]) ||
      (entry->spdu_sign.s[1] != spdu_sign->s[1])) {
    return false;
  }

  // 서명 Rx 값이 다르면 동일한 SPDU가 아니다. 빠르게 진행하기 위해 일단 2바이트만 비교한다.
  // 동일하지 않은 SPDU의 서명 Rx 값의 2바이트 값이 우연히 같을 경우, 아래 전체 비교문에서 다시 체크된다.
  if ((entry->spdu_sign.R_r.u.point.u.xy.x[0] != spdu_sign->R_r.u.point.u.xy.x[0]) ||
      (entry->spdu_sign.R_r.u.point.u.xy.x[1] != spdu_sign->R_r.u.point.u.xy.x[1])) {
    return false;
  }

  // 생성시각이 다르거나, 둘 중 하나에만 생성시각이 있으면 중복 SPDU가 아니다.
  // 둘 모두 생성시각이 없을 경우(entry->spdu_gen_time = spdu_gen_time = 0), 생성시각에 관련된 중복체크는 수행되지 않는다.
  if (entry->spdu_gen_time != spdu_gen_time) {
    return false;
  }

  // 서명 s 값이 다르면 동일한 SPDU가 아니다.
  if (memcmp(entry->spdu_sign.s, spdu_sign->s, sizeof(spdu_sign->s)) != 0) {
    return false;
  }

  // 서명 Rx 값이 다르면 동일한 SPDU가 아니다.
  if (memcmp(entry->spdu_sign.R_r.u.point.u.xy.x,
             spdu_sign->R_r.u.point.u.xy.x,
             sizeof(spdu_sign->R_r.u.point.u.xy.x)) != 0) {
    return false;
  }

  // 여기까지 도달하면 동일한 SPDU이다.
  return true;
}


/**
 * @brief 특정 SPDU 정보 집합에 대해, 동일한 정보를 갖는 Replay 체크 엔트리를 리스트 내에서 찾아 반환한다.
 * @param[in] list Replay 체크 리스트
 * @param[in] spdu_rx_time SPDU 수신 시각
 * @param[in] spdu_gen_time SPDU 생성 시각
 * @param[in] spdu_sign SPDU 서명
 * @param[in] valid_period 엔트리 유효기간. 엔트리 생성시점이 (현재시각 - 비교기간)보다 과거인 엔트리는 리스트에서 삭제 (비교대상 x)
 * @return 동일한 정보를 갖는 엔트리
 * @retval NULL: 동일한 엔트리가 존재하지 않음.
 */
struct Dot2SecProfileReplayCheckEntry INTERNAL * dot2_FindIdenticalSPDUInSecProfileReplayCheckList(
  struct Dot2SecProfileReplayCheckList *list,
  Dot2Time64 spdu_rx_time,
  Dot2Time64 spdu_gen_time,
  struct Dot2Signature *spdu_sign,
  Dot2Time64 valid_period)
{
  Log(kDot2LogLevel_Event, "Find identical SPDU in replay check list\n");
  struct Dot2SecProfileReplayCheckEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp)
  {
    // 엔트리 유효기간이 만료되었으면 리스트에서 제거한다. (비교되지 않는다)
    if ((spdu_rx_time > valid_period) &&
        (entry->entry_gen_time < (spdu_rx_time - valid_period))) {
      dot2_RemoveSecProfileReplayCheckEntry(list, entry);
      continue;
    }

    // 정보가 동일하면 엔트리를 반환한다.
    if (dot2_CheckIdenticalSecProfileReplayCheckEntry(entry, spdu_gen_time, spdu_sign) == true) {
      return entry;
    }
  }
  return NULL;
}
