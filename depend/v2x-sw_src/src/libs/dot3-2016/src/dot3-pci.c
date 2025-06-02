/**
 * @file
 * @brief Provider Channel Info 관련 기능 구현 파일
 * @date 2019-09-26
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3-types.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#include "dot3-mib.h"


/**
 * @brief EDCA Parameter Set을 기본값으로 설정한다.
 * @param[out] set 설정할 EDCA Parameter Set
 */
static void dot3_SetDefaultEDCAParameterSet(struct Dot3EDCAParameterSet *set)
{
  /*
   * AC_BE에 대한 기본값을 설정한다.(per IEEE 802.11)
   */
  struct Dot3EDCAParameterRecord *record = &(set->record[0]);
  record->aci = kDot3ACI_BE;
  record->acm = kDot3ACM_Default;
  record->aifsn = kDot3AIFSN_AC_BE;
  record->ecwmin = kDot3ECW_AC_BE_ECWMin;
  record->ecwmax = kDot3ECW_AC_BE_ECWMax;
  record->txoplimit = kDot3TXOPLimit_AC_BE;

  /*
   * AC_BK에 대한 기본값을 설정한다.(per IEEE 802.11)
   */
  record = &(set->record[1]);
  record->aci = kDot3ACI_BK;
  record->acm = kDot3ACM_Default;
  record->aifsn = kDot3AIFSN_AC_BK;
  record->ecwmin = kDot3ECW_AC_BK_ECWMin;
  record->ecwmax = kDot3ECW_AC_BK_ECWMax;
  record->txoplimit = kDot3TXOPLimit_AC_BK;

  /*
   * AC_VI에 대한 기본값을 설정한다.(per IEEE 802.11)
   */
  record = &(set->record[2]);
  record->aci = kDot3ACI_VI;
  record->acm = kDot3ACM_Default;
  record->aifsn = kDot3AIFSN_AC_VI;
  record->ecwmin = kDot3ECW_AC_VI_ECWMin;
  record->ecwmax = kDot3ECW_AC_VI_ECWMax;
  record->txoplimit = kDot3TXOPLimit_AC_VI;

  /*
   * AC_VO에 대한 기본값을 설정한다.(per IEEE 802.11)
   */
  record = &(set->record[3]);
  record->aci = kDot3ACI_VO;
  record->acm = kDot3ACM_Default;
  record->aifsn = kDot3AIFSN_AC_VO;
  record->ecwmin = kDot3ECW_AC_VO_ECWMin;
  record->ecwmax = kDot3ECW_AC_VO_ECWMax;
  record->txoplimit = kDot3TXOPLimit_AC_VO;
}


/**
 * @brief PCI(Provider Channel Info) 테이블 엔트리를 기본값으로 설정한다.
 * @param[in] chan_num 채널번호
 * @param[out] entry 설정할 PCI 엔트리
 *
 * 초기화 루틴을 제외하고는 provider 뮤텍스 락 상태에서 호출되어야 한다.\n
 * 필수정보 및 확장정보를 모두 설정한다. 단, 확장정보는 WSA의 Channel Info에 포함되지 않도록 값만 설정하고, present는 false로 설정한다.
 */
static void dot3_SetDefaultPCITableEntry(Dot3ChannelNumber chan_num, struct Dot3PCITableEntry *entry)
{
  struct Dot3PCI *pci = &(entry->pci);
  if ((chan_num % 2) == 0) {
    pci->operating_class = kDot3OperatingClass_5G_10MHz;
  } else {
    pci->operating_class = kDot3OperatingClass_5G_20MHz;
  }
  pci->chan_num = chan_num;
  pci->transmit_power_level = kDot3Power_MaxEIRPInClassC;
  pci->datarate = kDot3DataRate_TxDefault;
  pci->adaptable_datarate = true;
  pci->present.edca_param_set = false;
  pci->present.chan_access = false;
  dot3_SetDefaultEDCAParameterSet(&(pci->edca_param_set)); // 설정만 해 둔다.
  pci->chan_access = kDot3ProviderChannelAccess_AlternatingTimeSlot1Only; // 설정만 해 둔다.
}


/**
 * @brief PCI(Provider Channel Info) 테이블을 초기화한다.
 * @param[in] table PCI 테이블
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_InitPCITable(struct Dot3PCITable *table)
{
  Log(kDot3LogLevel_Init, "Initialize PCI table\n");
  memset(table, 0, sizeof(struct Dot3PCITable));
  TAILQ_INIT(&(table->head));

  /*
   * 각 10MHz/20MHz 채널에 대한 기본 PCI 정보들을 테이블에 추가한다.
   */
  struct Dot3PCITableEntry *entry;
  for (unsigned int i = kDot3ChannelNumber_KoreaV2XMin; i <= kDot3ChannelNumber_KoreaV2XMax; i++) {
    entry = (struct Dot3PCITableEntry *)calloc(1, sizeof(struct Dot3PCITableEntry));
    if (!entry) { return -kDot3Result_NoMemory; }
    dot3_SetDefaultPCITableEntry(i, entry);
    TAILQ_INSERT_TAIL(&(table->head), entry, entries);
    (table->num)++;
  }

  Log(kDot3LogLevel_Init, "Success to initialize PCI table\n");
  return kDot3Result_Success;
}


/**
 * @brief PCI(Provider Channel Info) 테이블을 비운다.
 * @param[in] table PCI 테이블
 */
void INTERNAL dot3_FlushPCITable(struct Dot3PCITable *table)
{
  Log(kDot3LogLevel_Event, "Flush PCI table\n");
  struct Dot3PCITableEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    free(entry);
  }
}


/**
 * @brief PCI 테이블에서 특정 채널번호를 갖는 PCI 엔트리를 찾아 반환한다.
 * @param[in] table PCI 테이블
 * @param[in] chan_num 찾고자 하는 채널번호
 * @retval NULL: 실패
 * @return 해당 엔트리의 포인터
 */
static struct Dot3PCITableEntry * dot3_FindPCIWithChannelNumber(struct Dot3PCITable *table, Dot3ChannelNumber chan_num)
{
  struct Dot3PCITableEntry *pci_entry;
  TAILQ_FOREACH(pci_entry, &(table->head), entries) {
    if (pci_entry->pci.chan_num == chan_num) {
      return pci_entry;
    }
  }
  return NULL;
}


/**
 * @brief PCI를 테이블에 추가하거나 업데이트한다.
 * @param[in] table PCI 테이블
 * @param[in] pci 추가하거나 업데이트할 PCI 정보구조체 포인터
 * @retval 양수: 테이블에 저장된 PCI 엔트리 총 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_AddOrUpdatePCI(struct Dot3PCITable *table, const struct Dot3PCI *pci)
{
  Log(kDot3LogLevel_Event, "Add or Update PCI (channel: %u)\n", pci->chan_num);

  /*
   * 테이블이 가득 차 있는지 확인한다.
   */
  if (table->num >= kDot3PCINum_Max) {
    Err("Fail to add PCI - table is full (%u)\n", table->num);
    return -kDot3Result_PCITableFull;
  }

  /*
   * 동일한 채널번호를 갖는 PCI를 테이블에서 찾는다.
   */
  struct Dot3PCITableEntry *pci_in_table = dot3_FindPCIWithChannelNumber(table, pci->chan_num);

  /*
   * 동일한 정보가 존재하지 않으면 PCI 엔트리를 추가한다.
   */
  if (pci_in_table == NULL) {
    pci_in_table = (struct Dot3PCITableEntry *)calloc(1, sizeof(struct Dot3PCITableEntry));
    if (pci_in_table == NULL) { return -kDot3Result_NoMemory; }
    TAILQ_INSERT_TAIL(&(table->head), pci_in_table, entries);
    ++(table->num);
    Log(kDot3LogLevel_Event, "PCI added - %d entries present\n", table->num);
  }

  /*
   * 동일한 정보가 존재하면 추가하지 않고 기존 정보를 업데이트 한다.
   */
  else {
    Log(kDot3LogLevel_Event, "PCI updated - %d entries present\n", table->num);
  }

  /*
   * PCI 정보를 저장한다.
   */
  memcpy(&(pci_in_table->pci), pci, sizeof(struct Dot3PCI));
  pci_in_table->pci.edca_param_set.record[0].aci = kDot3ACI_BE;
  pci_in_table->pci.edca_param_set.record[1].aci = kDot3ACI_BK;
  pci_in_table->pci.edca_param_set.record[2].aci = kDot3ACI_VI;
  pci_in_table->pci.edca_param_set.record[3].aci = kDot3ACI_VO;
  pci_in_table->option_cnt = 0;
  if (pci->present.edca_param_set) { pci_in_table->option_cnt++; }
  if (pci->present.chan_access) { pci_in_table->option_cnt++; }

  return (int)(table->num);
}


/**
 * @brief 특정 채널번호와 관련된 PCI 정보를 반환한다.
 * @param[in] table PCI 테이블
 * @param[in] chan_num 채널번호
 * @param[out] pci PCI 정보가 저장/반환될 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_GetPCIWithChannel(struct Dot3PCITable *table, Dot3ChannelNumber chan_num, struct Dot3PCI *pci)
{
  struct Dot3PCITableEntry *pci_entry = dot3_FindPCIWithChannelNumber(table, chan_num);
  if (pci_entry) {
    memcpy(pci, &(pci_entry->pci), sizeof(struct Dot3PCI));
    return kDot3Result_Success;
  }
  return -kDot3Result_NoSuchPCI;
}


/**
 * @brief 현재 테이블에 저장되어 있는 PCI 정보의 개수를 반환한다.
 * @param[in] table PCI 테이블
 * @return 테이블에 저장되어 있는 PCI 정보의 개수
 */
Dot3PCINum INTERNAL dot3_GetPCINum(struct Dot3PCITable *table)
{
  return table->num;
}
