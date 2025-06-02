/**
 * @file
 * @brief USR(User Service Request) 관련 기능 구현 파일
 * @date 2020-07-19
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdlib.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#include "dot3-mib.h"


/**
 * @brief USR 테이블을 초기화한다.
 * @param[in] table USR 테이블
 */
void INTERNAL dot3_InitUSRTable(struct Dot3USRTable *table)
{
  Log(kDot3LogLevel_Event, "Initialize USR table\n");
  memset(table, 0, sizeof(struct Dot3USRTable));
  TAILQ_INIT(&(table->head));
}


/**
 * @brief USR 테이블을 비운다.
 * @param[in] table USR 테이블
 */
void INTERNAL dot3_FlushUSRTable(struct Dot3USRTable *table)
{
  Log(kDot3LogLevel_Event, "Flush USR table\n");
  dot3_DeleteAllUSRs(table);
}


/**
 * @brief USR 테이블에서 특정 PSID를 갖는 USR 엔트리를 찾아 반환한다.
 * @param[in] table USR 테이블
 * @param[in] psid 찾고자 하는 PSID
 * @retval NULL: 실패
 * @return USR 엔트리 포인터
 */
static struct Dot3USRTableEntry* dot3_FindUSRWithPSID(struct Dot3USRTable *table, Dot3PSID psid)
{
  struct Dot3USRTableEntry *entry;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->usr.psid == psid) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief USR 테이블에서 모든 조건이 동일한 USR 엔트리를 찾아 반환한다.
 * @param[in] table USR 테이블
 * @param[in] psid 찾고자 하는 USR의 PSID
 * @param[in] wsa_type 찾고자 하는 USR의 WSA type
 * @param[in] src_mac_addr 찾고자 하는 USR의 송신지 MAC 주소
 * @param[in] chan_num 찾고자 하는 USR의 채널번호
 * @param[in] psc 찾고자 하는 USR의 PSC. 없을 경우에는 NULL을 전달한다.
 * @param[in] advertiser_id 찾고자 하는 USR의 Advertiser ID. 없을 경우에는 NULL을 전달한다.
 * @retval NULL: 실패
 * @return USR 엔트리 포인터
 *
 * USR에 등록된 필수정보와 옵션정보를 모두 비교한다.\n
 *  - 비교할 옵션정보가 NULL로 전달되면 비교하지 않는다.\n
 *  - 하지만, USR에 옵션정보가 저장되어 있는 경우에는 비교한다(따라서 NULL을 전달하면 동일하지 않은 것으로 결정된다).\n
 */
struct Dot3USRTableEntry INTERNAL *dot3_FindMatchedUSR(
  struct Dot3USRTable *table,
  Dot3PSID psid,
  Dot3WSAType wsa_type,
  const Dot3MACAddress src_mac_addr,
  Dot3ChannelNumber chan_num,
  const struct Dot3PSC *psc,
  const struct Dot3WSAAdvertiserID *advertiser_id)
{
  struct Dot3USRTableEntry *entry;
  struct Dot3USR *usr;
  TAILQ_FOREACH(entry, &(table->head), entries)
  {
    usr = &(entry->usr);
    if ((usr->psid == psid) && (usr->wsa_type == wsa_type))
    {
      if (usr->present.src_mac_addr == true) {
        if (dot3_CompareMACAddress(usr->src_mac_addr, src_mac_addr) == false) {
          return NULL;
        }
      }
      if (usr->present.chan_num == true) {
        if (usr->chan_num != chan_num) {
          return NULL;
        }
      }
      if (usr->present.psc == true) {
        if ((psc == NULL) || (dot3_ComparePSC(&(usr->psc), psc) == false)) {
          return NULL;
        }
      }
      if (usr->present.advertiser_id == true) {
        if ((advertiser_id == NULL) || (dot3_CompareAdvertiserID(&(usr->advertiser_id), advertiser_id) == false)) {
          return NULL;
        }
      }
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief USR 엔트리를 테이블에 추가한다.
 * @param[in] table USR 테이블
 * @param[in] usr 추가할 USR 정보구조체 포인터
 * @retval 양수: 테이블에 저장된 USR 엔트리의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_AddUSREntry(struct Dot3USRTable *table, const struct Dot3USR *usr)
{
  /*
   * USR 엔트리 메모리를 할당하고 정보를 저장한다.
   */
  struct Dot3USRTableEntry *usr_entry = (struct Dot3USRTableEntry *)calloc(1, sizeof(struct Dot3USRTableEntry));
  if (usr_entry == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(&usr_entry->usr, usr, sizeof(struct Dot3USR));

  /*
   * 엔트리를 테이블에 추가한다.
   */
  TAILQ_INSERT_TAIL(&(table->head), usr_entry, entries);
  table->num++;
  return (int)(table->num);
}


/**
 * @brief USR을 테이블에 추가한다.
 * @param[in] table USR 테이블
 * @param[in] usr 추가할 USR 정보구조체 포인터
 * @retval 양수: 테이블에 저장된 USR의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_AddUSR(struct Dot3USRTable *table, const struct Dot3USR *usr)
{
  Log(kDot3LogLevel_Event, "Add USR (psid: %u)\n", usr->psid);

  /*
   * 테이블 오버플로우를 확인한다.
   */
  if (table->num >= kDot3USRNum_Max) {
    Err("Fail to add USR - table is full (%u)\n", table->num);
    return -kDot3Result_USRTableFull;
  }

  /*
   * 동일한 PSID를 갖는 USR이 이미 저장되어 있는지 확인한다.
   */
  if(dot3_FindUSRWithPSID(table, usr->psid)) {
    Err("Fail to add USR - USR with same psid(%u) exists in table\n", usr->psid);
    return -kDot3Result_DuplicatedUSR;
  }

  /*
   * USR 엔트리를 테이블에 추가한다.
   */
  int ret = dot3_AddUSREntry(table, usr);
  if (ret < 0) {
    return ret;
  }

  /*
   * 테이블에 저장된 USR 엔트리 개수를 반환한다.
   */
  Log(kDot3LogLevel_Event, "Success to add USR - %d entries present\n", ret);
  return ret;
}


/**
 * @brief USR을 테이블에서 삭제한다.
 * @param[in] table USR 테이블
 * @param[in] psid 삭제할 USR의 PSID
 * @retval 양수: 테이블에 남아 있는 USR의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_DeleteUSR(struct Dot3USRTable *table, Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Delete USR (psid: %u)\n", psid);

  /*
   * 테이블 내에서 동일한 PSID를 갖는 USR 엔트리를 찾아 제거한다.
   */
  struct Dot3USRTableEntry *entry = dot3_FindUSRWithPSID(table, psid);
  if (entry) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    free(entry);
    (table->num)--;
  } else {
    Err("Fail to delete USR - no such USR (psid: %u)\n", psid);
    return -kDot3Result_NoSuchUSR;
  }

  Log(kDot3LogLevel_Event, "Success to delete USR - %u entries present\n", table->num);
  return (int)(table->num);
}


/**
 * @brief 테이블 내 모든 USR들을 삭제한다.
 * @param[in] table USR 테이블
 */
void INTERNAL dot3_DeleteAllUSRs(struct Dot3USRTable *table)
{
  Log(kDot3LogLevel_Event, "Delete all USRs\n");

  /*
   * 테이블 내 모든 USR들을 삭제한다.
   */
  struct Dot3USRTableEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    free(entry);
  }
  table->num = 0;
}


/**
 * @brief 특정 PSID를 갖는 USR 정보를 반환한다.
 * @param[in] table USR 테이블
 * @param[in] psid 확인하고자 하는 USR의 PSID
 * @param[out] usr USR 정보가 저장되어 반환될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_GetUSRWithPSID(struct Dot3USRTable *table, Dot3PSID psid, struct Dot3USR *usr)
{
  Log(kDot3LogLevel_Event, "Get USR with psid %u\n", psid);

  /*
   * 테이블 내에서 동일한 PSID를 갖는 USR을 찾아 반환한다.
   */
  struct Dot3USRTableEntry *entry = dot3_FindUSRWithPSID(table, psid);
  if (entry) {
    memcpy(usr, &entry->usr, sizeof(struct Dot3USR));
  } else {
    Err("Fail to get USR - no such USR with psid %u\n", psid);
    return -kDot3Result_NoSuchUSR;
  }

  Log(kDot3LogLevel_Event, "Success to get USR\n");
  return kDot3Result_Success;
}


/**
 * @brief 현재 테이블에 저장되어 있는 USR의 개수를 반환한다.
 * @param[in] table USR 테이블
 * @return USR의 개수
 */
Dot3USRNum INTERNAL dot3_GetUSRNum(struct Dot3USRTable *table)
{
  return table->num;
}
