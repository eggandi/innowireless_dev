/**
 * @file
 * @brief PSR(Provider Service Request) 관련 기능 구현 파일
 * @date 2019-08-16
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
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
 * @brief PSR 테이블을 초기화한다.
 * @param[in] table PSR 테이블
 */
void INTERNAL dot3_InitPSRTable(struct Dot3PSRTable *table)
{
  Log(kDot3LogLevel_Event, "Initialize PSR table\n");
  memset(table, 0, sizeof(struct Dot3PSRTable));
  TAILQ_INIT(&(table->head));
}


/**
 * @brief PSR 테이블을 비운다.
 * @param[in] table PSR 테이블
 */
void INTERNAL dot3_FlushPSRTable(struct Dot3PSRTable *table)
{
  Log(kDot3LogLevel_Event, "Flush PSR table\n");
  dot3_DeleteAllPSRs(table);
}


/**
 * @brief PSR 테이블에서 특정 PSID를 갖는 PSR을 찾아 반환한다.
 * @param[in] table PSR 테이블
 * @param[in] psid 찾고자 하는 PSID
 * @retval NULL: 실패
 * @return PSR 엔트리 포인터
 */
static struct Dot3PSRTableEntry* dot3_FindPSRWithPSID(struct Dot3PSRTable *table, Dot3PSID psid)
{
  struct Dot3PSRTableEntry *entry;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->psr.psid == psid) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief PSR 엔트리를 테이블에 추가한다.
 * @param[in] table PSR 테이블
 * @param[in] psr 추가할 PSR 정보구조체 포인터
 * @retval 양수: 테이블에 저장된 PSR 엔트리의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_AddPSREntry(struct Dot3PSRTable *table, const struct Dot3PSR *psr)
{
  /*
   * PSR 엔트리 메모리를 할당하고 정보를 저장한다.
   */
  struct Dot3PSRTableEntry *psr_entry = (struct Dot3PSRTableEntry *)calloc(1, sizeof(struct Dot3PSRTableEntry));
  if (psr_entry == NULL) {
    return -kDot3Result_NoMemory;
  }
  memcpy(&psr_entry->psr, psr, sizeof(struct Dot3PSR));
  if (psr->ip_service) { psr_entry->option_cnt += 2; }
  if (psr->present.psc) { psr_entry->option_cnt++; }
  if (psr->present.provider_mac_addr) { psr_entry->option_cnt++; }
  if (psr->present.rcpi_threshold) { psr_entry->option_cnt++; }
  if (psr->present.wsa_cnt_threshold) { psr_entry->option_cnt++; }
  if (psr->present.wsa_cnt_threshold_interval) { psr_entry->option_cnt++; }

  /*
   * PSR의 서비스채널과 동일한 채널번호를 갖는 Channel info 정보를 참조한다.
   */
  bool found = false;
  struct Dot3PCITableEntry *pci_entry;
  TAILQ_FOREACH(pci_entry, &(g_dot3_mib.provider_info.pci_table.head), entries) {
    if (psr->service_chan_num == pci_entry->pci.chan_num) {
      psr_entry->pci_entry = pci_entry;
      Log(kDot3LogLevel_Event, "Channel info for channel %d is referenced - %p\n",
          psr->service_chan_num, psr_entry->pci_entry);
      found = true;
      break;
    }
  }
  if (found == false) {
    Err("Fail to add PSR - cannot find channel info for service channel %d\n", psr->service_chan_num);
    free(psr_entry);
    return -kDot3Result_NoRelatedChannelInfo;
  }

  /*
   * 엔트리를 테이블에 추가한다.
   */
  TAILQ_INSERT_TAIL(&(table->head), psr_entry, entries);
  table->num++;
  return (int)(table->num);
}


/**
 * @brief PSR을 테이블에 추가한다.
 * @param[in] table PSR 테이블
 * @param[in] psr 추가할 PSR 정보구조체 포인터
 * @retval 양수: 테이블에 저장된 PSR의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_AddPSR(struct Dot3PSRTable *table, const struct Dot3PSR *psr)
{
  Log(kDot3LogLevel_Event, "Add PSR (psid: %u)\n", psr->psid);

  /*
   * 테이블 오버플로우를 확인한다.
   */
  if (table->num >= kDot3PSRNum_Max) {
    Err("Fail to add PSR - table is full (%u)\n", table->num);
    return -kDot3Result_PSRTableFull;
  }

  /*
   * 동일한 PSID를 갖는 PSR이 이미 저장되어 있는지 확인한다.
   */
  if(dot3_FindPSRWithPSID(table, psr->psid)) {
    Err("Fail to add PSR - PSR with same psid(%u) exists in table\n", psr->psid);
    return -kDot3Result_DuplicatedPSR;
  }

  /*
   * PSR 엔트리를 테이블에 추가한다.
   */
  int ret = dot3_AddPSREntry(table, psr);
  if (ret < 0) {
    return ret;
  }

  /*
   * 테이블에 저장된 PSR 엔트리 개수를 반환한다.
   */
  Log(kDot3LogLevel_Event, "Success to add PSR - %d entries present\n", ret);
  return ret;
}


/**
 * @brief PSR을 테이블에서 삭제한다.
 * @param[in] table PSR 테이블
 * @param[in] psid 삭제할 PSR의 PSID
 * @retval 양수: 테이블에 남아 있는 PSR의 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_DeletePSR(struct Dot3PSRTable *table, Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Delete PSR (psid: %u)\n", psid);

  /*
   * 테이블 내에서 동일한 PSID를 갖는 PSR 엔트리를 찾아 제거한다.
   */
  struct Dot3PSRTableEntry *entry = dot3_FindPSRWithPSID(table, psid);
  if (entry) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    free(entry);
    (table->num)--;
  } else {
    Err("Fail to delete PSR - no such PSR (psid: %u)\n", psid);
    return -kDot3Result_NoSuchPSR;
  }

  Log(kDot3LogLevel_Event, "Success to delete PSR - %u entries present\n", table->num);
  return (int)(table->num);
}


/**
 * @brief 테이블 내 특정 PSR의 PSC 정보를 변경한다.
 * @param[in] table PSR 테이블
 * @param[in] psid 변경할 PSR의  PSID
 * @param[in] psc 변경할 PSC 문자열
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_ChangePSR(struct Dot3PSRTable *table, Dot3PSID psid, const char *psc)
{
  Log(kDot3LogLevel_Event, "Change PSC of PSR(PSID: %u) to %s\n", psid, psc);

  /*
   * 테이블 내에서 해당 PSID를 갖는 PSR을 찾아 업데이트한다.
   */
  struct Dot3PSRTableEntry *entry = dot3_FindPSRWithPSID(table, psid);
  if (entry) {
    memset(entry->psr.psc.psc, 0, sizeof(entry->psr.psc.psc));
    entry->psr.psc.len = (Dot3PSCLen)strlen(psc);
    memcpy(entry->psr.psc.psc, psc, entry->psr.psc.len);
  } else {
    Err("Fail to change PSC of PSR(PSID: %u)\n", psid);
    return -kDot3Result_NoSuchPSR;
  }

  Log(kDot3LogLevel_Event, "Success to change PSC\n");
  return kDot3Result_Success;
}


/**
 * @brief 테이블 내 모든 PSR들을 삭제한다.
 * @param[in] table PSR 테이블
 */
void INTERNAL dot3_DeleteAllPSRs(struct Dot3PSRTable *table)
{
  Log(kDot3LogLevel_Event, "Delete all PSRs\n");

  /*
   * 테이블 내 모든 PSR들을 삭제한다.
   */
  struct Dot3PSRTableEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    free(entry);
  }
  table->num = 0;
}


/**
 * @brief 특정 PSID를 갖는 PSR 정보를 반환한다.
 * @param[in] table PSR 테이블
 * @param[in] psid 확인하고자 하는 PSR 의 PSID
 * @param[out] psr PSR 정보가 저장되어 반환될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_GetPSRWithPSID(struct Dot3PSRTable *table, Dot3PSID psid, struct Dot3PSR *psr)
{
  Log(kDot3LogLevel_Event, "Get PSR with psid %u\n", psid);

  /*
   * 테이블 내에서 동일한 PSID를 갖는 PSR을 찾아 반환한다.
   */
  struct Dot3PSRTableEntry *entry = dot3_FindPSRWithPSID(table, psid);
  if (entry) {
    memcpy(psr, &entry->psr, sizeof(struct Dot3PSR));
  } else {
    Err("Fail to get PSR - no such PSR with psid %u\n", psid);
    return -kDot3Result_NoSuchPSR;
  }

  Log(kDot3LogLevel_Event, "Success to get PSR\n");
  return kDot3Result_Success;
}


/**
 * @brief 현재 테이블에 저장되어 있는 PSR의 개수를 반환한다.
 * @param[in] table PSR 테이블
 * @return PSR의 개수
 */
Dot3PSRNum INTERNAL dot3_GetPSRNum(struct Dot3PSRTable *table)
{
  return table->num;
}
