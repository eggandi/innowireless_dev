/** 
  * @file 
  * @brief 타 장치(End-Entity) 인증서캐시 관련 기능 구현
  * @date 2022-07-03 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "sudo_queue.h"
#include "openssl/sha.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "dot2-cert-info-inline.h"


/**
 * @brief EE인증서캐시 H1 리스트를 초기화한다.
 * @param[in] list 초기화할 H1 기스트
 */
void INTERNAL dot2_InitEECertCacheH1List(struct Dot2EECertCacheH1List *list)
{
  list->entry_num = 0;
  list->max_entry_num = kDot2EECertCacheEntryNum_Max;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief EE인증서캐시 테이블을 초기화한다.
 */
void INTERNAL dot2_InitEECertCacheTable(void)
{
  Log(kDot2LogLevel_Event, "Initialize EE cert cache table\n");
  struct Dot2EECertCacheTable *table = &(g_dot2_mib.ee_cert_cache_table);
  for (int i = 0; i < EE_CERT_H1_CACHE_LIST_NUM; i++) {
    dot2_InitEECertCacheH1List(&(table->list[i]));
  }
  table->entry_num = 0;
  table->max_entry_num = kDot2EECertCacheEntryNum_Max;
}


/**
 * @brief EE인증서캐시 H1 리스트를 해제한다.
 * @param[in] list 초기화할 H1 기스트
 */
void INTERNAL dot2_ReleaseEECertCacheH1List(struct Dot2EECertCacheH1List *list)
{
  struct Dot2EECertCacheEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    dot2_ClearEECertCacheEntry(entry);
    free(entry);
  }
  list->entry_num = 0;
}


/**
 * @brief EE인증서캐시 테이블을 해제한다.
 */
void INTERNAL dot2_ReleaseEECertCacheTable(void)
{
  Log(kDot2LogLevel_Event, "Release EE cert cache table\n");
  struct Dot2EECertCacheTable *table = &(g_dot2_mib.ee_cert_cache_table);
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  for (int i = 0; i < EE_CERT_H1_CACHE_LIST_NUM; i++) {
    dot2_ReleaseEECertCacheH1List(&(table->list[i]));
  }
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}


/**
 * @brief EE 인증서캐시엔트리를 인증서캐시리스트에 삽입한다.
 * @param[in] entry 삽입할 인증서케시엔트리
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_PushEECertCacheEntry(struct Dot2EECertCacheEntry *entry)
{
  uint8_t h1 = DOT2_GET_SHA256_H1(entry->cert_h.octs);
  Log(kDot2LogLevel_Event, "Push EE cert("H8_FMT") cache entry to table[%02X]\n",
      H8_FMT_ARGS(DOT2_GET_SHA256_H8(entry->cert_h.octs)), h1);

  struct Dot2EECertCacheTable *table = &(g_dot2_mib.ee_cert_cache_table);

  /*
   * 테이블이 가득 차 있으면 실패를 반환한다.
   */
  if (table->entry_num >= table->max_entry_num) {
    Err("Fail to push EE cert cache entry - too may entry in table (max: %u)\n", table->max_entry_num);
    return -kDot2Result_SPDU_TooManyEECertCache;
  }

  /*
   * 인증서캐시엔트리가 삽입될 H1 리스트를 찾는다.
   */
  struct Dot2EECertCacheH1List *list = &(table->list[h1]);

  /*
   * 리스트가 가득 차 있으면 실패를 반환한다.
   */
  if (list->entry_num >= list->max_entry_num) {
    Err("Fail to push EE cert cache entry - too may entry in list (max: %u)\n", list->max_entry_num);
    return -kDot2Result_SPDU_TooManyEECertCache;
  }

  /*
   * H1 리스트에 인증서정보엔트리를 삽입한다.
   */
  TAILQ_INSERT_TAIL(&(list->head), entry, entries);
  list->entry_num++;
  table->entry_num++;

  Log(kDot2LogLevel_Event, "Success to push EE cert cache entry (list: %u, table: %u)\n", list->entry_num, table->entry_num);
  return kDot2Result_Success;
}


/**
 * @brief EE 인증서의 인증서체인을 구성한다.
 * @param[in] entry EE 인증서 캐시 엔트리
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCodE): 실패
 */
int INTERNAL dot2_ConstructEECertChain(struct Dot2EECertCacheEntry *entry)
{
  if (entry->issuer) {
    Log(kDot2LogLevel_Event, "Skip construct EE cert chain - already constructed\n");
    return kDot2Result_Success;
  }

  struct Dot2SCCCertInfoEntry *issuer = dot2_FindSCCCertWithHashedID8(entry->contents.common.issuer.h8);
  if (issuer == NULL) {
    Log(kDot2LogLevel_Event, "Fail to construct EE cert chain - issuer("H8_FMT") is not in SCC cert table\n",
        H8_FMT_ARGS(DOT2_GET_SHA256_H8(issuer->cert_h.octs)));
    return -kDot2Result_SPDU_ConstructCertChain;
  }

  Log(kDot2LogLevel_Event, "Success to construct EE cert chain - issuer: "H8_FMT"\n",
      H8_FMT_ARGS(DOT2_GET_SHA256_H8(issuer->cert_h.octs)));
  entry->issuer = issuer;
  return kDot2Result_Success;
}


/**
 * @brief 타 장치(EE) 인증서정보 캐시를 제거한다.
 * @param[in] exp 기준이 되는 만기시각
 */
void INTERNAL dot2_RemoveExpiredEECertCache(Dot2Time64 exp)
{
  Log(kDot2LogLevel_Event, "Remove expired EE cert cache - exp: %"PRIu64"\n", exp);
  struct Dot2EECertCacheTable *table = &(g_dot2_mib.ee_cert_cache_table);
  struct Dot2EECertCacheH1List *list;
  struct Dot2EECertCacheEntry *entry, *tmp;
  for (unsigned int i = 0; i < EE_CERT_H1_CACHE_LIST_NUM; i++) {
    list = &(table->list[i]);
    TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
      if ((entry->contents.common.valid_end < exp) ||
          (entry->expiry < exp)) {
        TAILQ_REMOVE(&(list->head), entry, entries);
        dot2_ClearEECertCacheEntry(entry);
        free(entry);
        list->entry_num--;
        table->entry_num--;
      }
    }
  }
}
