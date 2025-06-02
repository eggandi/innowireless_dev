/**
 * @file
 * @brief WSR(WSM Service Request) 관련 API들을 구현한 파일
 * @date 2019-08-16
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief WSR을 등록한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid WSR 저장소에 등록할 PSID
 * @retval 1 이상: (WSR 추가 후) 현재 등록되어 있는 WSR의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_AddWSR(Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Add WSR (psid: %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidPSID(psid) == false) {
    Err("Fail to add WSR - invalid PSID %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * WSR을 테이블에 추가한다.
   */
  struct Dot3WSRTable *table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(table->mtx));
  int ret = dot3_AddWSR(table, psid);
  pthread_mutex_unlock(&(table->mtx));
  return ret;
}


/**
 * @brief 등록되어 있는 WSR을 삭제한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 삭제할 WSR의 PSID
 * @retval 0 이상: (WSR 삭제 후) 현재 등록되어 있는 WSR의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_DeleteWSR(Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Delete WSR (psid: %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidPSID(psid) == false) {
    Err("Fail to delete WSR - invalid PSID %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * WSR을 테이블에서 제거한다.
   */
  struct Dot3WSRTable *table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(table->mtx));
  int ret = dot3_DeleteWSR(table, psid);
  pthread_mutex_unlock(&(table->mtx));
  return ret;
}


/**
 * @brief 등록되어 있는 모든 WSR들을 삭제한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot3_DeleteAllWSRs(void)
{
  Log(kDot3LogLevel_Event, "Delete all WSRs\n");

  /*
   * 모든 WSR들을 테이블에서 제거한다.
   */
  struct Dot3WSRTable *table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(table->mtx));
  dot3_DeleteAllWSRs(table);
  pthread_mutex_unlock(&(table->mtx));
}


/**
 * @brief 특정 PSID를 갖는 WSR이 등록되어 있는지 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 확인하고자 하는 PSID
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_CheckWSRWithPSID(Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Check WSR with PSID %u\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidPSID(psid) == false) {
    Err("Fail to check WSR with PSID - invalid psid %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  struct Dot3WSRTable *table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(table->mtx));
  struct Dot3WSRTableEntry *entry = dot3_FindWSRWithPSID(table, psid);
  pthread_mutex_unlock(&(table->mtx));
  if (entry == NULL) {
    Err("Fail to check WSR with PSID %u\n", psid);
    return -kDot3Result_NoSuchWSR;
  }
  Log(kDot3LogLevel_Event, "Success to check WSR\n");
  return kDot3Result_Success;
}


/**
 * @brief 등록되어 있는 WSR의 개수를 확인한다(상세 내용 API 매뉴얼 참조).
 * @return 등록되어 있는 WSR의 개수(0 이상)
 */
Dot3WSRNum OPEN_API Dot3_GetWSRNum(void)
{
  return dot3_GetWSRNum(&(g_dot3_mib.wsr_table));
}
