/** 
  * @file 
  * @brief Rotate CMH 관련 구현
  * @date 2022-07-07 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-cmh-inline.h"
#include "certificate/cert-info/dot2-cert-info-inline.h"


/**
 * @brief Rotate CMH 세트 리스트를 초기화한다.
 * @param[in] list Rotate CMH 리스트
 */
void INTERNAL dot2_InitRotateCMHSetList(struct Dot2RotateCMHSetList *list)
{
  Log(kDot2LogLevel_Event, "Initialize rotate CMH set list\n");
  list->entry_num = 0;
  list->max_entry_num = kDot2RotateCMHSetEntryNum_Max;
  list->active_set = NULL;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief Rotate CMH 세트 리스트를 해제한다.
 * @param[in] list Rotate CMH 리스트
 */
void INTERNAL dot2_ReleaseRotateCMHSetList(struct Dot2RotateCMHSetList *list)
{
  Log(kDot2LogLevel_Event, "Release rotate CMH set list\n");
  struct Dot2RotateCMHSetEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    dot2_ClearRotateCMHSetEntry(entry);
    free(entry);
  }
  list->entry_num = 0;
  list->active_set = NULL;
}


/**
 * @brief Rotate CMH 세트 엔트리의 내용을 제거한다.
 * @param[in] entry Rotate CMH 세트 엔트리
 */
void INTERNAL dot2_ClearRotateCMHSetEntry(struct Dot2RotateCMHSetEntry *entry)
{
  dot2_ClearRotateCMHSetCommonInfo(&(entry->common));
  for (unsigned int i = 0; i < entry->info_num; i++) {
    dot2_ClearRotateCMHInfo(&(entry->cmh[i]));
  }
  entry->info_num = 0;
  entry->max_info_num = kDot2RotateCMHInfoNum_PseudonymCertDefault;
  entry->active_cmh = NULL;
  entry->issuer = NULL;
}


/**
 * @brief Rotate CMH 세트 엔트리를 제거한다.
 * @param[in] entry Rotate CMH 세트 엔트리
 */
void INTERNAL dot2_ReleaseRotateCMHSetEntry(struct Dot2RotateCMHSetEntry *entry)
{
  dot2_ClearRotateCMHSetEntry(entry);
  free(entry);
}


/**
 * @brief Rotate CMH 세트 공통정보의 내용을 제거한다.
 * @param[in] info Rotate CMH 세트 공통정보
 */
void INTERNAL dot2_ClearRotateCMHSetCommonInfo(struct Dot2RotateCMHSetCommonInfo *info)
{
  memset(info, 0, sizeof(struct Dot2RotateCMHSetCommonInfo));
}


/**
 * @brief Rotate CMH 정보의 내용을 제거한다.
 * @param[in] info Rotate CMH 정보
 */
void INTERNAL dot2_ClearRotateCMHInfo(struct Dot2RotateCMHInfo *info)
{
  dot2_ClearRotateCMHIndividualInfo(&(info->info));
  if (info->cert) {
    free(info->cert);
  }
#if defined(_FFASN1C_)
  if (info->asn1_cert) {
    asn1_free_value(asn1_type_dot2Certificate, info->asn1_cert);
  }
#elif defined(_OBJASN1C_)
  if ((info->asn1_cert) &&
      (info->ctxt)) {
    rtFreeContext(info->ctxt);
    free(info->ctxt);
  }
#else
#error "3rd party asn.1 library is not defined"
#endif
  memset(info, 0, sizeof(struct Dot2RotateCMHInfo));
}


/**
 * @brief Rotate CMH 개별정보의 내용을 제거한다.
 * @param[in] info Rotate CMH 개별정보
 */
void INTERNAL dot2_ClearRotateCMHIndividualInfo(struct Dot2RotateCMHIndividualInfo *info)
{
  dot2_ClearCertId(&(info->id));
  if (info->eck_priv_key) {
    EC_KEY_free(info->eck_priv_key);
  }
  memset(info, 0, sizeof(struct Dot2RotateCMHIndividualInfo));
}


/**
 * @brief Rotate CMH 세트 엔트리를 Rotate CMH 리스트에 삽입한다.
 * @param[in] cmh_type CMH 유형
 * @param[in] entry 저장할 CMH 세트 엔트리
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 리스트 내 CMH 세트 엔트리들은 유효기간 시작시점을 기준으로 오름차순으로 정렬된다. \n
 * 즉, 유효기간 시작시점이 빠를수록 테이블의 앞쪽에 위치한다.
 */
int INTERNAL dot2_PushRotateCMHSetEntry(Dot2CMHType cmh_type, struct Dot2RotateCMHSetEntry *entry)
{
  Log(kDot2LogLevel_Event, "Push rotate CMH set entry\n");

  /*
   * 엔트리를 저장할 리스트를 선택한다.
   */
  struct Dot2RotateCMHSetList *list = dot2_SelectRotateCMHSetList(cmh_type);
  if (!list) {
    Err("Fail to push rotate CMH set entry - conflict CMH type - prev: %u, cur: %u\n",
        g_dot2_mib.cmh_table.cmh_type, cmh_type);
    return -kDot2Result_CMH_ConflictCMHType;
  }

  /*
   * 리스트 오버플로우를 확인한다.
   */
  if (list->entry_num >= list->max_entry_num) {
    Err("Fail to push rotate CMH set entry - list is full(max: %u)\n", list->max_entry_num);
    return -kDot2Result_CMH_RotateCMHSetListIsFull;
  }

  /*
   * 테이블 내의 유효기간에 맞는 위치에 삽입한다.
   */
  Dot2Time64 valid_start = entry->common.valid_start;
  struct Dot2RotateCMHSetEntry *tmp;
  bool pushed = false;
  TAILQ_FOREACH_REVERSE(tmp, &(list->head), Dot2RotateCMHSetEntryHead, entries) {
    // 내 유효기간 시작시점이 동일하거나 크면 뒤에 삽입
    if (valid_start >= tmp->common.valid_start) {
      TAILQ_INSERT_AFTER(&(list->head), tmp, entry, entries);
      list->entry_num++;
      pushed = true;
      break;
    }
  }
  // 내 유효기간 시작시점이 제일 빠르면 제일 앞에 삽입한다.
  if (pushed == false) {
    TAILQ_INSERT_HEAD(&(list->head), entry, entries);
    list->entry_num++;
  }

  /*
   * 테이블의 CMH 유형을 저장한다.
   */
  g_dot2_mib.cmh_table.cmh_type = cmh_type;
  Log(kDot2LogLevel_Event, "Success to push rotate CMH set entry - cmh_type: %u\n", cmh_type);
  return kDot2Result_Success;
}


/**
 * @brief 특정 rotate CMH 세트가 현재 가용한지 확인한다.
 * @param[in] now 현재 시각
 * @param[in] entry 확인할 rotate CMH 세트 엔트리
 * @return 가용 여부
 *
 * 가용조건: 현재시각이 유효기간 내에 포함되어야 함.
 */
static inline bool dot2_CheckRotateCMHSetAvailableNow(Dot2Time64 now, struct Dot2RotateCMHSetEntry *entry)
{
  return ((now >= entry->common.valid_start) && (now <= entry->common.valid_end)) ? true : false;
}


/**
 * @brief 현 시점에 가용한 Rotate CMH 세트 엔트리를 반환한다.
 * @param[in] list Rotate CMH 세트 엔트리 리스트
 * @param[in] now 현재 시각
 * @param[out] set_changed 활성 CMH 세트가 변경되었는지 여부가 저장될 변수 포인터
 * @retval CMH 세트 엔트리 포인터: 성공
 * @retval NULL: 실패
 *
 * 가용조건 : 현재시각이 유효기간 내여야 한다.
 */
static struct Dot2RotateCMHSetEntry *
dot2_GetCurrentlyAvailableRotateCMHSetEntry(struct Dot2RotateCMHSetList *list, Dot2Time64 now, bool *set_changed)
{
  Log(kDot2LogLevel_Event, "Get currently available rotate CMH set entry, current TAI(%"PRIu64")\n", now);

  struct Dot2RotateCMHSetEntry *entry;
  struct Dot2RotateCMHSetEntry *found = NULL;
  *set_changed = false;

  /*
   * 기존에 사용 중이던 활성 CMH 세트가 있을 경우, 현재시각과 CMH 세트 유효기간을 비교하여 아직도 가용한지 확인한다.
   */
  bool use_new_active_cmh_set = true;
  if (list->active_set) {
    if (dot2_CheckRotateCMHSetAvailableNow(now, list->active_set)) {
      Log(kDot2LogLevel_Event, "Previous active rotate CMH set is still available - use it.\n");
      use_new_active_cmh_set = false;
      *set_changed = false;
    } else {
      Log(kDot2LogLevel_Event, "Previous active rotate CMH set is not available any more - finding the other one\n");
      *set_changed = true;
    }
  }

  /*
   * 기존 활성 CMH 세트가 가용하지 않아 새로운 활성 CMH 세트를 선택해야 할 경우,
   * 현 시점에 가용한 CMH 세트가 있는지 리스트에서 검색한다.
   */
  if (use_new_active_cmh_set) {
    TAILQ_FOREACH(entry, &(list->head), entries) {
      if (dot2_CheckRotateCMHSetAvailableNow(now, entry)) {
        Log(kDot2LogLevel_Event, "Success to find new available rotate CMH set(%"PRIu64" ~ %"PRIu64")\n",
            entry->common.valid_start, entry->common.valid_end);
        found = entry;
        break;
      }
    }
    if (found == NULL) {
      Err("Fail to find new available rotate CMH set for current TAI(%"PRIu64")\n", now);
      list->active_set = NULL;
      return NULL;
    }
    if (list->active_set) {
      list->active_set->active_cmh = NULL; // 기존 활성 CMH 세트 정보를 초기화한다.
    }
    list->active_set = found; // 현 시점에 가용한 CMH 세트를 새로운 활성 CMH 세트로 설정
    list->active_set->active_cmh = NULL; // 새로운 활성 CMH 세트의 활성 CMH가 아직 없음.
  }
  return list->active_set;
}


/**
 * @brief 현재 사용 중인 CMH 세트가 다음번 서명주기 전에 만료될지 여부를 확인한다.
 * @param[in] now 현재시각 (=이번 서명생성시각)
 * @param[in] valid_end CMH 세트 만료시각
 * @param[in] interval 서명생성주기(밀리초단위). 주기가 0일 경우, 판단할 수 없으므로 "만료되지 않음(false)"이 반환된다.
 * @return 다음번 서명주기 전에 만료되는지 여부
 */
static inline bool dot2_CheckCMHSetExpirationInNextTime(Dot2Time64 now, Dot2Time64 valid_end, unsigned int interval)
{
  if (interval != 0) {
    Dot2Time64 next_sign_time_usec = now + ((Dot2Time64)interval * 1000ULL);
    if (next_sign_time_usec > valid_end) {
      return true;
    }
  }
  return false;
}


/**
 * @brief rotate CMH 세트 엔트리 정보에 특정 PSID가 포함되어 있는지 확인한다.
 * @param[in] cmh_entry 확인할 CMH 세트 엔트리
 * @param[in] psid 확인할 PSID
 * @return 포함되어 있는지 여부
 */
static inline bool dot2_CheckRotateCMHSetEntry_PSID(const struct Dot2RotateCMHSetEntry *entry, Dot2PSID psid)
{
  bool psid_match = false;
  for (unsigned int i = 0; i < entry->common.psid_num; i++) {
    if (psid == entry->common.psid[i]) {
      psid_match = true;
      break;
    }
  }
  return psid_match;
}


/**
 * @brief "Week rotate CMH 세트" 내에서 현재의 활성 CMH 대신 다른 CMH를 활성 CMH로 설정한다.(그리고 선택된 CMH 엔트리를 반환한다)
 * @param[in] cmh_set "Week rotate CMH 세트"
 * @param[out] cmh_changed 활성 CMH가 변경되었는지 여부가 저장될 변수 포인터
 * @return 새롭게 선택된 CMH 엔트리
 * @retval NULL: 실패
 */
static inline struct Dot2RotateCMHInfo * dot2_SelectNextRotateCMHInfo(struct Dot2RotateCMHSetEntry *entry)
{
  // 랜덤한 인덱스의 CMH를 선택한다.
  // 기존에 사용 중인 CMH가 있고, 새로 선택된 인덱스가 기존 CMH의 인덱스와 동일하면 다를때까지 랜던하게 선택한다.
  uint8_t idx;
  struct Dot2RotateCMHInfo *new_active_cmh;
  do {
    idx = dot2_GetRandomOct(g_dot2_mib.rng_dev.name) % (uint8_t)(entry->info_num);
    new_active_cmh = &(entry->cmh[idx]);
  } while(new_active_cmh == entry->active_cmh);

  entry->active_cmh = new_active_cmh;
  Log(kDot2LogLevel_Event, "Set next week rotate CMH[%u]: "H8_FMT"\n",
      idx, H8_FMT_ARGS(DOT2_GET_SHA256_H8(new_active_cmh->cert_h.octs)));
  return new_active_cmh;
}


/**
 * @brief 사용할 Rotate CMH 정보를 선택한다.
 * @param[in] entry Rotate CMH 세트 엔트리
 * @param[in] cmh_change CMH 변경 요청 여부
 * @return 선택된 Rotate CMH 정보 포인터
 */
static struct Dot2RotateCMHInfo * dot2_SelectActiveRotateCMHInfo(struct Dot2RotateCMHSetEntry *entry, bool cmh_change)
{
  struct Dot2RotateCMHInfo *cmh_info;
  if ((cmh_change == true) ||
      (entry->active_cmh == NULL)) {
    Log(kDot2LogLevel_Event, "Select new active CMH\n");
    cmh_info = dot2_SelectNextRotateCMHInfo(entry);
  } else {
    Log(kDot2LogLevel_Event, "Use current active CMH\n");
    cmh_info = entry->active_cmh;
  }
  return cmh_info;
}


/**
 * @brief 가용한 Rotate CMH 정보를 가져온다.
 * @param[in] psid PSID
 * @param[in] now 가용 여부를 판단하기 위한 시점
 * @param[in] interval CMH를 이용한 서명 생성 주기(밀리초 단위)
 * @param[in] cmh_change CMH 변경 요청 여부
 * @param[out] cert_h 가용 CMH 내에 저장되어 있는 인증서 해시가 복사될 버퍼 포인터
 * @param[out] eck_priv_key 가용 CMH 내에 저장되어 있는 개인키가 복사될 구조체 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] asn1_cert 가용 CMH 내에 저장되어 있는 인증서 asn.1 정보가 복사될 구조체 포인터 (사용 후 free()해 주어야 한다)
 *                       objasn1 사용시에는 복사되지 않고 참조포인터만 반환된다 (즉, 사용 후 free() 해서는 안된다)
 * @param[out] cmh_changed CMH가 변경되었는지 여부가 반환될 변수 포인터
 * @param[out] cmh_expiry 현 시점에 CMH가 만기되었는지 여부 또는 다음번 서명생성주기에 CMH가 만기될지 여부가 반환될 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_GetAvailableRotateCMHInfo(
  Dot2PSID psid,
  Dot2Time64 now,
  unsigned int interval,
  bool cmh_change,
  struct Dot2SHA256 *cert_h,
  EC_KEY **eck_priv_key,
  void **asn1_cert,
  bool *cmh_changed,
  bool *cmh_expiry)
{
  Log(kDot2LogLevel_Event, "Get available rotate CMH info (PSID: %u, now: "PRIu64"\n", psid, now);

  struct Dot2RotateCMHSetList *list = &(g_dot2_mib.cmh_table.pseudonym_id);
  *cmh_changed = false;
  *cmh_expiry = false;

  /*
   * 현 시점에 가용한 CMH 세트 엔트리를 찾는다.
   */
  bool set_changed;
  struct Dot2RotateCMHSetEntry *cmh_entry = dot2_GetCurrentlyAvailableRotateCMHSetEntry(list, now, &set_changed);
  if (cmh_entry == NULL) {
    return -kDot2Result_SPDU_NoAvailableCMH;
  }
  if (cmh_change == true) { // CMH 변경을 요청받았d으면, CMH가 변경되었음을 반환한다.
    *cmh_changed = true;
  }
  if (set_changed == true) { // 유효기간 만기로 인해 CMH세트가 변경된 경우, CMH가 변경되었음을 반환하고, 변경이 기대
    *cmh_changed = true;
    *cmh_expiry = true;
  }

  /*
   * 다음번 서명 시점에 본 CMH 세트의 유효기간이 만기되는지 확인한다.
   */
  if (dot2_CheckCMHSetExpirationInNextTime(now, cmh_entry->common.valid_end, interval)) {
    *cmh_expiry = true;
  }

  /*
   * CMH 세트 내에 일치하는 PSID가 존재하는지 확인한다.
   */
  if (dot2_CheckRotateCMHSetEntry_PSID(cmh_entry, psid) == false) {
    Err("Fail to get available rotate CMH info - no matched PSID\n");
    cmh_entry->active_cmh = NULL;
    list->active_set = NULL;
    return -kDot2Result_SPDU_NoAvailableCMH;
  }

  /*
   * 어플리케이션으로부터 CMH 변경을 요청받았거나, 새로운 CMH세트가 선택되었거나, 선택된 CMH 세트에 활성 CMH가 없는 경우,
   * 새로운 활성 CMH를 선택한다.
   */
  struct Dot2RotateCMHInfo * cmh_info = dot2_SelectActiveRotateCMHInfo(cmh_entry, cmh_change);

  /*
   * CMH 정보를 복사/반환한다.
   */
  memcpy(cert_h->octs, cmh_info->cert_h.octs, DOT2_SHA_256_LEN);
  *eck_priv_key = EC_KEY_dup(cmh_info->info.eck_priv_key);
  if (*eck_priv_key == NULL) {
    Err("Fail to get available rotate CMH info - EC_KEY_dup() failed\n");
    return -kDot2Result_SPDU_CopyCMHECKEY;
  }
#if defined(_FFASN1C_)
  *asn1_cert = asn1_clone_value(asn1_type_dot2Certificate, cmh_info->asn1_cert);
#elif defined(_OBJASN1C_)
  *asn1_cert = cmh_info->asn1_cert;
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (*asn1_cert == NULL) {
    Err("Fail to get available rotate CMH info - asn1_cert copy failed\n");
    EC_KEY_free(*eck_priv_key);
    return -kDot2Result_SPDU_CopyCMHAsn1Cert;
  }

  Log(kDot2LogLevel_Event, "Success to get available rotate CMH info\n");
  return kDot2Result_Success;
}


/**
 * @brief 만기된 Rotate CMH Set을 리스트에서 제거한다.
 * @param[in] exp 기준이 되는 만기시각
 * @param[in] list Rotate CMH Set 리스트
 */
void INTERNAL dot2_RemoveExpiredRotateCMHSet(Dot2Time64 exp, struct Dot2RotateCMHSetList *list)
{
  Log(kDot2LogLevel_Event, "Remove expired rotate CMH set - exp: %"PRIu64"\n", exp);
  struct Dot2RotateCMHSetEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    if (entry->common.valid_end < exp) {
      TAILQ_REMOVE(&(list->head), entry, entries);
      dot2_ClearRotateCMHSetEntry(entry);
      if (entry == list->active_set) {
        list->active_set = NULL;
      }
      list->entry_num--;
      free(entry);
    }
  }
}
