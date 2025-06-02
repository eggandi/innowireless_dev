/**
  * @file
  * @brief 해시 기반 CRL 관련 구현
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
 * @brief 해시 기반 CRL H1 리스트를 초기화한다.
 * @param[in] list 해시 기반 CRL H1 리스트
 */
static void dot2_InitHashBasedCRLH1List(struct Dot2HashBasedCRLH1List *list)
{
  list->entry_num = 0;
  list->max_entry_num = kDot2CertRevocationEntryNum_Max;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief 해시 기반 CRL 테이블을 초기화한다.
 * @param[in] table 해시 기반 CRL 테이블
 */
void INTERNAL dot2_InitHashBasedCRLTable(struct Dot2HashBasedCRLTable *table)
{
  Log(kDot2LogLevel_Event, "Initialize hash based CRL table\n");
  for (unsigned int i = 0; i < HASH_CERT_REVOCATION_LIST_NUM; i++) {
    dot2_InitHashBasedCRLH1List(&(table->list[i]));
  }
}


/**
 * @brief 해시 기반 CRL H1 리스트를 비운다.
 * @param[in] list 해시 기반 CRL H1 리스트
 */
static void dot2_FlushHashBasedCRLH1List(struct Dot2HashBasedCRLH1List *list)
{
  struct Dot2HashBasedCertRevocationEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    free(entry);
  }
  list->entry_num = 0;
}


/**
 * @brief 해시 기반 CRL 테이블을 비운다.
 * @param[in] table 해시 기반 CRL 테이블
 */
void INTERNAL dot2_FlushHashBasedCRLTable(struct Dot2HashBasedCRLTable *table)
{
  Log(kDot2LogLevel_Event, "Flush hash based CRL table\n");
  for (unsigned int i = 0; i < HASH_CERT_REVOCATION_LIST_NUM; i++) {
    dot2_FlushHashBasedCRLH1List(&(table->list[i]));
  }
}


/**
 * @brief 해시 기반 인증서폐기정보 테이블에서 특정 H10을 갖는 인증서폐기정보 엔트리를 찾는다.
 * @param[in] table 인증서폐기정보 테이블
 * @param[in] h10 폐기된 인증서에 대한 H10값
 * @return 인증서폐기정보 엔트리 포인터
 * @retval NULL: 해당 엔트리가 존재하지 않을 경우
 */
struct Dot2HashBasedCertRevocationEntry INTERNAL *dot2_FindHashBasedCertRevocationEntry(
  struct Dot2HashBasedCRLTable *table,
  const uint8_t *h10)
{
  uint8_t h1 = *(h10 + 9);
  struct Dot2HashBasedCRLH1List *list = &(table->list[h1]);
  struct Dot2HashBasedCertRevocationEntry *entry;
  TAILQ_FOREACH(entry, &(list->head), entries) {
    if (memcmp(entry->h10, h10, 10) == 0) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief 해시기반 인증서폐기정보 테이블에 인증서폐기정보 엔트리를 생성/저장한다.
 * @param[in] table 인증서폐기정보 테이블
 * @param[in] h10 폐기인증서 H10
 * @return 인증서폐기정보 엔트리 포인터
 * @retval NULL: 실패
 */
static struct Dot2HashBasedCertRevocationEntry * dot2_PushHashBasedCertRevocationEntry(
  struct Dot2HashBasedCRLTable *table,
  const uint8_t *h10)
{
  Log(kDot2LogLevel_Event, "Add Hash based cert revocation entry - 0x%02X%02X...%02X%02X\n",
      *(h10), *(h10 + 1), *(h10 + 8), *(h10 + 9));

  uint8_t h1 = *(h10 + 9);
  struct Dot2HashBasedCRLH1List *list = &(table->list[h1]);

  /*
   * 리스트가 가득 차 있으면 실패를 반환한다.
   */
  if (list->entry_num >= list->max_entry_num) {
    Err("Fail to add Hash based cert revocation entry - list is full\n");
    return NULL;
  }

  /*
   * 엔트리를 생성하여 리스트에 저장한다.
   */
  struct Dot2HashBasedCertRevocationEntry *entry = calloc(1, sizeof(struct Dot2HashBasedCertRevocationEntry));
  assert(entry);
  if (entry) {
    memcpy(entry->h10, h10, 10);
    TAILQ_INSERT_TAIL(&(list->head), entry, entries);
    list->entry_num++;
  }
  return entry;
}


/**
 * @brief 해시 기반 인증서폐기정보 엔트리를 테이블에 추가한다. 이미 존재할 경우 추가하지 않는다.
 * @param[in] h10 폐기인증서의 H10 값
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddHashBasedCertRevocationEntry(const uint8_t *h10)
{
  Log(kDot2LogLevel_Event, "Add Hash based cert revocation\n");
  struct Dot2HashBasedCRLTable *table = &(g_dot2_mib.crl.hash);
  struct Dot2HashBasedCertRevocationEntry *entry = dot2_FindHashBasedCertRevocationEntry(table, h10);
  if (entry == NULL) {
    entry = dot2_PushHashBasedCertRevocationEntry(table, h10);
  }
  return (entry ? kDot2Result_Success : -kDot2Result_CRL_Add);
}
