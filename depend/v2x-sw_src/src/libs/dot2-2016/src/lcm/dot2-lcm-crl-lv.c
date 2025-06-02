/**
  * @file
  * @brief LV(Linkage Value) 기반 CRL 관련 구현
  * @date 2023-01-08
  * @author gyun
  */


// 시스템 헤더 파일
#include <assert.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief LV 기반 CRL 테이블을 초기화한다.
 * @param[in] table LV 기반 CRL 테이블
 */
void INTERNAL dot2_InitLVBasedCRLTable(struct Dot2LVBasedCRLTable *table)
{
  table->entry_num = 0;
  table->max_entry_num = kDot2LVBasedCRLEntryNum_Max;
  TAILQ_INIT(&(table->head));
}


/**
 * @brief LV 기반 인증서폐기리스트를 초기화한다.
 * @param[in] list 초기화할 리스트
 */
static void dot2_InitLVBasedCertRevocationList(struct Dot2LVBasedCertRevocationList *list)
{
  list->entry_num = 0;
  list->max_entry_num = kDot2CertRevocationEntryNum_Max;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief LV 기반 CRL 정보 엔트리를 초기화한다.
 * @param[in] entry 초기화할 엔트리
 * @param[in] i_period 엔트리의 i-period 값
 */
static void dot2_InitLVBasedCRLEntry(struct Dot2LVBasedCRLEntry *entry, uint32_t i_period)
{
  entry->i = i_period;
  for (unsigned int i = 0; i < LV_CERT_REVOCATION_LIST_NUM; i++) {
    dot2_InitLVBasedCertRevocationList(&(entry->list[i]));
  }
}


/**
 * @brief LV 기반 인증서폐기정보 리스트를 비운다.
 * @param[in] list LV 기반 인증서폐기정보 리스트
 */
void INTERNAL dot2_FlushLVBasedCertRevocationList(struct Dot2LVBasedCertRevocationList *list)
{
  struct Dot2LVBasedCertRevocationEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    free(entry);
  }
  list->entry_num = 0;
}


/**
 * @brief LV 기반 CRL 엔트리를 제거한다.
 * @param[in] entry LV 기반 CRL 엔트리
 */
static void dot2_FreeLVBasedCRLEntry(struct Dot2LVBasedCRLEntry *entry)
{
  for (unsigned int i = 0; i < LV_CERT_REVOCATION_LIST_NUM; i++) {
    dot2_FlushLVBasedCertRevocationList(&(entry->list[i]));
  }
  free(entry);
}


/**
 * @brief LV 기반 CRL 테이블을 비운다.
 * @param[in] table LV 기반 CRL 테이블
 */
void INTERNAL dot2_FlushLVBasedCRLTable(struct Dot2LVBasedCRLTable *table)
{
  Log(kDot2LogLevel_Event, "Flush LV based CRL table\n");
  struct Dot2LVBasedCRLEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    TAILQ_REMOVE(&(table->head), entry, entries);
    dot2_FreeLVBasedCRLEntry(entry);
  }
  table->entry_num = 0;
}


/**
 * @brief LV 기반 CRL 테이블에서 특정 i-period를 갖는 CRL 엔트리를 찾는다.
 * @param[in] i_period 폐기인증서의 i-period(=iCert) 값
 * @return CRL 엔트리 포인터
 * @retval NULL: 해당되는 엔트리가 존재하지 않음
 */
static inline struct Dot2LVBasedCRLEntry * dot2_FindLVBasedCRLEntry(uint32_t i_period)
{
  struct Dot2LVBasedCRLTable *table = &(g_dot2_mib.crl.lv);
  struct Dot2LVBasedCRLEntry *entry;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->i == i_period) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief LV 기반 CRL 엔트리 내에서 특정 LV를 갖는 인증서폐기정보 엔트리를 찾는다.
 * @param[in] crl_entry CRL 엔트리
 * @param[in] lv 폐기인증서 LV 값
 * @return 인증서폐기정보 엔트리
 * @retval NULL: 해당 엔트리가 존재하지 않음
 */
static inline struct Dot2LVBasedCertRevocationEntry *dot2_FindLVBasedCertRevocationEntry_1(
  struct Dot2LVBasedCRLEntry *crl_entry,
  const uint8_t *lv)
{
  const uint8_t lv1 = *(lv + (DOT2_LINKAGE_VALUE_LEN - 1));
  struct Dot2LVBasedCertRevocationList *list = &(crl_entry->list[lv1]);
  struct Dot2LVBasedCertRevocationEntry *entry;
  TAILQ_FOREACH(entry, &(list->head), entries) {
    if (memcmp(entry->lv, lv, DOT2_LINKAGE_VALUE_LEN) == 0) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief LV 기반 CRL 테이블 내에서 특정 i_period와 LV를 갖는 인증서폐기정보 엔트리를 찾는다.
 * @param[in] table LV 기반 CRL 테이블
 * @param[in] i_period 폐기인증서 i 값
 * @param[in] lv 폐기인증서 LV 값
 * @return 인증서폐기정보 엔트리
 * @retval NULL: 해당 엔트리가 존재하지 않음
 */
struct Dot2LVBasedCertRevocationEntry INTERNAL *
dot2_FindLVBasedCertRevocationEntry_2(struct Dot2LVBasedCRLTable *table, uint32_t i_period, const uint8_t *lv)
{
  struct Dot2LVBasedCRLEntry *crl_entry;
  struct Dot2LVBasedCertRevocationEntry *entry = NULL;
  TAILQ_FOREACH(crl_entry, &(table->head), entries) {
    if (crl_entry->i == i_period) {
      entry = dot2_FindLVBasedCertRevocationEntry_1(crl_entry, lv);
      break;
    }
  }
  return entry;
}


/**
 * @brief LV CRL 엔트리 정보에 인증서폐기정보를 생성/저장한다.
 * @param[in] crl_entry 인증서폐기정보를 저장할 CRL 엔트리 정보
 * @param[in] lv 폐기인증서의 LV 값 (인증서폐기정보)
 * @return 추가된 CRL 엔트리 정보
 * @retval NULL: 실패
 */
struct Dot2LVBasedCertRevocationEntry INTERNAL *
dot2_PushLVBasedCertRevocationEntry(struct Dot2LVBasedCRLEntry *crl_entry, const uint8_t *lv)
{
  /*
   * LV 값의 마지막 바이트로 추가할 리스트를 결정한다.
   */
  uint8_t lv1 = *(lv + (DOT2_LINKAGE_VALUE_LEN - 1));
  struct Dot2LVBasedCertRevocationList *list = &(crl_entry->list[lv1]);

  /*
   * 리스트가 가득 차 있으면 실패한다.
   */
  if (list->entry_num >= list->max_entry_num) {
    Err("Fail to push LV based cert revocation entry - list is full\n");
    return NULL;
  }

  /*
   * 엔트리를 생성하여 리스트에 추가한다.
   */
  struct Dot2LVBasedCertRevocationEntry *entry = calloc(1, sizeof(struct Dot2LVBasedCertRevocationEntry));
  assert(entry);
  if (entry) {
    memcpy(entry->lv, lv, DOT2_LINKAGE_VALUE_LEN);
    TAILQ_INSERT_TAIL(&(list->head), entry, entries);
    list->entry_num++;
  }

  Log(kDot2LogLevel_Event, "Success to push LV based cert revocation entry in list[%u] - entry num: %u\n",
      lv1, list->entry_num);

  return entry;
}


/**
 * @brief LV 기반 CRL 테이블에 특정 i-period 값에 대한 CRL 엔트리를 생성/저장한다.
 * @param[in] table CRL 엔트리를 저장할 CRL 테이블
 * @param[in] i_period 폐기인증서 i-period 값
 * @return 추가된 CRL 엔트리
 * @retval NULL: 실패
 */
struct Dot2LVBasedCRLEntry INTERNAL * dot2_PushLVBasedCRLEntry(struct Dot2LVBasedCRLTable *table, uint32_t i_period)
{
  /*
   * CRL 테이블이 가득 차 있으면 실패한다.
   */
  if (table->entry_num >= table->max_entry_num) {
    Err("Fail to push LV based CRL entry - table is full");
    return NULL;
  }

  /*
   * 엔트리를 생성하여 리스트에 추가한다.
   */
  struct Dot2LVBasedCRLEntry *entry = calloc(1, sizeof(struct Dot2LVBasedCRLEntry));
  assert(entry);
  if (entry) {
    dot2_InitLVBasedCRLEntry(entry, i_period);
    TAILQ_INSERT_TAIL(&(table->head), entry, entries);
    table->entry_num++;
  }
  return entry;
}


/**
 * @brief LV 기반 인증서폐기정보 엔트리를 테이블에 추가한다. 이미 존재할 경우 추가하지 않는다.
 * @param[in] i_period 폐기인증서의 i-period(=iCert) 값
 * @param[in] lv 폐기인증서의 LV 값
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddLVBasedCertRevocationEntry(uint32_t i_period, const uint8_t *lv)
{
  Log(kDot2LogLevel_Event, "Add LV based cert revocation entry - i: %u, LV: 0x%02X%02X...%02X%02X\n",
      i_period, *(lv), *(lv + 1), *(lv + DOT2_LINKAGE_VALUE_LEN - 2), *(lv + DOT2_LINKAGE_VALUE_LEN - 1));
  struct Dot2LVBasedCRLTable *table = &(g_dot2_mib.crl.lv);
  struct Dot2LVBasedCertRevocationEntry *entry = NULL;
  struct Dot2LVBasedCRLEntry *crl_entry = dot2_FindLVBasedCRLEntry(i_period);
  if (crl_entry) {
    entry = dot2_FindLVBasedCertRevocationEntry_1(crl_entry, lv);
  } else {
    crl_entry = dot2_PushLVBasedCRLEntry(table, i_period);
  }
  if (crl_entry &&
      (entry == NULL)) {
    entry = dot2_PushLVBasedCertRevocationEntry(crl_entry, lv);
  }

  return (entry ? kDot2Result_Success:-kDot2Result_CRL_Add);
}
