/**
 * @file
 * @brief WSR(WSM Service Request) 관련 기능 구현 파일
 * @date 2020-07-14
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdlib.h>
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#include "dot3-mib.h"


/**
 * @brief WSR 테이블을 초기화한다.
 * @param[in] table WSR 테이블
 */
void INTERNAL dot3_InitWSRTable(struct Dot3WSRTable *table)
{
  memset(table, 0, sizeof(struct Dot3WSRTable));
  TAILQ_INIT(&(table->head));
  pthread_mutex_init(&(table->mtx), NULL);
}


/**
 * @brief WSR 테이블을 비운다.
 * @param[in] table WSR 테이블
 */
void INTERNAL dot3_FlushWSRTable(struct Dot3WSRTable *table)
{
  dot3_DeleteAllWSRs(table);
}


/**
 * @brief WSR 테이블에서 특정 PSID를 갖는 WSR을 찾아 반환한다.
 * @param[in] table WSR 테이블
 * @param[in] psid 찾고자 하는 PSID
 * @retval NULL: 실패
 * @return 해당 엔트리의 포인터
 */
struct Dot3WSRTableEntry INTERNAL * dot3_FindWSRWithPSID(struct Dot3WSRTable *table, Dot3PSID psid)
{
  struct Dot3WSRTableEntry *entry;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->wsr.psid == psid) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief WSR 엔트리를 테이블에 추가한다.
 * @param[in] table WSR 테이블
 * @param[in] psid 추가할 WSR의 PSID
 * @retval 양수: 테이블에 저장된 WSR 엔트리의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_AddWSREntry(struct Dot3WSRTable *table, Dot3PSID psid)
{
  /*
   * WSR 엔트리 메모리를 할당하고 정보를 저장한다.
   */
  struct Dot3WSRTableEntry *entry = (struct Dot3WSRTableEntry *)calloc(1, sizeof(struct Dot3WSRTableEntry));
  if (entry == NULL) {
    return -kDot3Result_NoMemory;
  }
  entry->wsr.psid = psid;

  /*
   * 엔트리를 테이블에 추가한다.
   */
  TAILQ_INSERT_TAIL(&(table->head), entry, entries);
  table->num++;
  return (int)(table->num);
}


/**
 * @brief WSR을 테이블에 추가한다.
 * @param[in] table WSR 테이블
 * @param[in] psid 추가할 WSR의 PSID
 * @retval 양수: 테이블에 저장된 WSR의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_AddWSR(struct Dot3WSRTable *table, Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Add WSR (psid: %u)\n", psid);

  /*
   * 테이블 오버플로우를 확인한다.
   */
  if (table->num >= kDot3WSRNum_Max) {
    Err("Fail to add WSR - table is full (%u)\n", table->num);
    return -kDot3Result_WSRTableFull;
  }

  /*
   * 동일한 PSID를 갖는 WSR이 이미 저장되어 있는지 확인한다.
   */
  if(dot3_FindWSRWithPSID(table, psid)) {
    Err("Fail to add WSR - WSR with same psid(%u) exists in table\n", psid);
    return -kDot3Result_DuplicatedWSR;
  }

  /*
   * WSR 엔트리를 테이블에 추가한다.
   */
  int ret = dot3_AddWSREntry(table, psid);
  if (ret < 0) {
    return ret;
  }

  /*
   * 테이블에 저장된 WSR 엔트리 개수를 반환한다.
   */
  Log(kDot3LogLevel_Event, "Success to add WSR - %d entries present\n", ret);
  return ret;
}


/**
 * @brief WSR을 테이블에서 삭제한다.
 * @param[in] table WSR 테이블
 * @param[in] psid 삭제할 WSR의 PSID
 * @retval 양수: 테이블에 남아 있는 WSR의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_DeleteWSR(struct Dot3WSRTable *table, Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Delete WSR (psid: %u)\n", psid);

  /*
   * 테이블 내에서 동일한 PSID를 갖는 WSR 엔트리를 찾는다.
   */
  struct Dot3WSRTableEntry *entry, *tmp, *del = NULL;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    if (entry->wsr.psid == psid) {
      TAILQ_REMOVE(&(table->head), entry, entries);
      (table->num)--;
      del = entry;
      break;
    }
  }

  /*
   * 찾으면 삭제하고, 못 찾으면 실패를 반환한다.
   */
  if (del) {
    free(del);
  } else {
    Err("Fail to delete WSR - no such WSR (psid: %u)\n", psid);
    return -kDot3Result_NoSuchWSR;
  }

  Log(kDot3LogLevel_Event, "Success to delete WSR - %d entries present\n", table->num);
  return (int)(table->num);
}


/**
 * @brief 테이블 내 모든 WSR들을 삭제한다.
 * @param[in] table WSR 테이블
 */
void INTERNAL dot3_DeleteAllWSRs(struct Dot3WSRTable *table)
{
  Log(kDot3LogLevel_Event, "Delete all WSRs\n");

  /*
   * 테이블 내 모든 WSR들을 삭제한다.
   */
  struct Dot3WSRTableEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    free(entry);
  }
  table->num = 0;
}


/**
 * @brief 현재 테이블에 저장되어 있는 WSR의 개수를 반환한다.
 * @param[in] table WSR 테이블
 * @return 테이블에 저장되어 있는 WSR의 개수
 */
Dot3WSRNum INTERNAL dot3_GetWSRNum(struct Dot3WSRTable *table)
{
  return table->num;
}
