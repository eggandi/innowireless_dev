/** 
 * @file
 * @brief Sequential CMH 관련 구현
 * @date 2020-05-14
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-cmh-inline.h"
#include "certificate/cert-info/dot2-cert-info-inline.h"


/**
 * @brief Sequential CMH 리스트를 초기화한다.
 */
void INTERNAL dot2_InitSequentialCMHList(struct Dot2SequentialCMHList *list)
{
  Log(kDot2LogLevel_Init, "Initialize sequential CMH list\n");
  list->entry_num = 0;
  list->max_entry_num = kDot2SequentialCMHEntryNum_Max;
  list->active_cmh = NULL;
  TAILQ_INIT(&(list->head));
}


/**
 * @brief Sequential CMH 리스트를 해제한다.
 */
void INTERNAL dot2_ReleaseSequentialCMHList(struct Dot2SequentialCMHList *list)
{
  Log(kDot2LogLevel_Init, "Release sequential CMH list\n");
  struct Dot2SequentialCMHEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    TAILQ_REMOVE(&(list->head), entry, entries);
    dot2_ClearSequentialCMHEntry(entry);
    free(entry);
  }
  list->entry_num = 0;
  list->max_entry_num = kDot2SequentialCMHEntryNum_Max;
  list->active_cmh = NULL;
}


/**
 * @brief Sequential CMH 엔트리의 내용을 제거한다.
 * @param[in] entry Sequential CMH 엔트리
 */
void INTERNAL dot2_ClearSequentialCMHEntry(struct Dot2SequentialCMHEntry *entry)
{
  dot2_ClearSequentialCMHInfo(&(entry->info));
  if (entry->cert) {
    free(entry->cert);
    entry->cert = NULL;
  }
  entry->cert_size = 0;
  memset(&(entry->cert_h), 0, sizeof(entry->cert_h));
  entry->issuer = NULL;

#if defined(_FFASN1C_)
  if (entry->asn1_cert) {
    asn1_free_value(asn1_type_dot2Certificate, entry->asn1_cert);
    entry->asn1_cert = NULL;
  }
#elif defined(_OBJASN1C_)
  if ((entry->asn1_cert) &&
      (entry->ctxt)) {
    rtFreeContext(entry->ctxt);
    free(entry->ctxt);
  }
  entry->asn1_cert = NULL;
  entry->ctxt = NULL;
#else
#error "3rd party asn.1 library is not defined"
#endif
}


/**
 * @brief Sequential CMH 엔트리를 제거한다.
 * @param[in] entry Sequential CMH 엔트리
 */
void INTERNAL dot2_ReleaseSequentialCMHEntry(struct Dot2SequentialCMHEntry *entry)
{
  dot2_ClearSequentialCMHEntry(entry);
  free(entry);
}


/**
 * @brief Sequential CMH 정보의 내용을 제거한다.
 * @param[in] info Sequential CMH 정보
 */
void INTERNAL dot2_ClearSequentialCMHInfo(struct Dot2SequentialCMHInfo *info)
{
  dot2_ClearEECertContents(&(info->cert_contents));
  if (info->eck_priv_key) {
    EC_KEY_free(info->eck_priv_key);
  }
  memset(info, 0, sizeof(struct Dot2SequentialCMHInfo));
}


/**
 * @brief Sequenential CMH 엔트리를 Sequential CMH 리스트에 삽입한다.
 * @param[in] cmh_type CMH 유형
 * @param[in] entry 저장할 CMH 엔트리
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * 리스트 내 CMH 엔트리들은 유효기간 시작시점을 기준으로 오름차순으로 정렬된다. \n
 * 즉, 유효기간 시작시점이 빠를수록 테이블의 앞쪽에 위치한다.
 */
int INTERNAL dot2_PushSequentialCMHEntry(Dot2CMHType cmh_type, struct Dot2SequentialCMHEntry *entry)
{
  Log(kDot2LogLevel_Event, "Push sequential CMH entry\n");

  /*
   * 엔트리를 저장할 리스트를 선택한다.
   */
  struct Dot2SequentialCMHList *list = dot2_SelectSequentialCMHList(cmh_type);
  if (!list) {
    Err("Fail to push sequential CMH entry - conflict CMH type - prev: %u, cur: %u\n",
        g_dot2_mib.cmh_table.cmh_type, cmh_type);
    return -kDot2Result_CMH_ConflictCMHType;
  }

  /*
   * 리스트 오버플로우를 확인한다.
   */
  if (list->entry_num >= list->max_entry_num) {
    Err("Fail to push sequential CMH entry - list is full(max: %u)\n", list->max_entry_num);
    return -kDot2Result_CMH_SequentialCMHListIsFull;
  }

  /*
   * 테이블 내의 유효기간에 맞는 위치에 삽입한다.
   */
  Dot2Time64 valid_start = entry->info.cert_contents.common.valid_start;
  struct Dot2SequentialCMHEntry *tmp;
  bool pushed = false;
  TAILQ_FOREACH_REVERSE(tmp, &(list->head), Dot2SequentialCMHEntryHead, entries) {
    // 내 유효기간 시작시점이 동일하거나 크면 뒤에 삽입
    if (valid_start >= tmp->info.cert_contents.common.valid_start) {
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
  if ((cmh_type == kDot2CMHType_Application) ||
      (cmh_type == kDot2CMHType_Identification) ||
      (cmh_type == kDot2CMHType_Pseudonym)) {
    g_dot2_mib.cmh_table.cmh_type = cmh_type;
  }
  Log(kDot2LogLevel_Event, "Success to push sequential CMH entry - cmh_type: %u\n", cmh_type);
  return kDot2Result_Success;
}


/**
 * @brief 현 시점에 가용한 Sequential CMH 엔트리를 반환한다.
 * @param[in] list Sequential CMH 엔트리 리스트
 * @param[in] now 현재 시각
 * @retval CMH 엔트리 포인터: 성공
 * @retval NULL: 실패
 *
 * 가용조건 : 현재시각이 유효기간 내여야 한다.
 */
struct Dot2SequentialCMHEntry INTERNAL *
dot2_GetCurrentlyAvailableSequentialCMHEntry(struct Dot2SequentialCMHList *list, Dot2Time64 now)
{
  Log(kDot2LogLevel_Event, "Get currently available sequential CMH entry, current TAI(%"PRIu64")\n", now);
  struct Dot2SequentialCMHEntry *entry;
  struct Dot2SequentialCMHEntry *found = NULL;

  /*
   * 기존에 사용 중이던 활성 CMH가 있을 경우, 현재시각과 CMH 유효기간을 비교하여 아직도 가용한지 확인한다.
   */
  bool use_new_active_cmh = true;
  if (list->active_cmh) {
    if (dot2_CheckSequentialCMHAvailableNow(now, list->active_cmh)) {
      Log(kDot2LogLevel_Event, "Previous active sequential CMH is still available - use it.\n");
      use_new_active_cmh = false;
    } else {
      Log(kDot2LogLevel_Event, "Previous active sequential CMH is not available any more - finding the other one\n");
    }
  }

  /*
   * 기존 활성 CMH가 가용하지 않아 새로운 활성 CMH를 선택해야 할 경우,
   * 현 시점에 가용한 CMH가 있는지 리스트에서 검색한다.
   */
  if (use_new_active_cmh) {
    TAILQ_FOREACH(entry, &(list->head), entries) {
      if (dot2_CheckSequentialCMHAvailableNow(now, entry)) {
        Log(kDot2LogLevel_Event, "Success to find new available sequential CMH(%"PRIu64" ~ %"PRIu64")\n",
            entry->info.cert_contents.common.valid_start, entry->info.cert_contents.common.valid_end);
        found = entry;
        break;
      }
    }
    if (found == NULL) {
      Err("Fail to find new available sequential CMH for current TAI(%"PRIu64")\n", now);
      list->active_cmh = NULL;
      return NULL;
    }
    list->active_cmh = found; // 현 시점에 가용한 CMH를 새로운 활성 CMH로 설정
  }
  return list->active_cmh;
}


/**
 * @brief sequential CMH 엔트리 정보에 특정 PSID가 포함되어 있는지 확인한다.
 * @param[in] cmh_entry 확인할 CMH 엔트리
 * @param[in] psid 확인할 PSID
 * @return 포함되어 있는지 여부
 */
static inline bool dot2_CheckSequentialCMHEntry_PSID(const struct Dot2SequentialCMHEntry *cmh_entry, Dot2PSID psid)
{
  bool psid_match = false;
  const struct Dot2EECertPermissions *app_perms = &(cmh_entry->info.cert_contents.app_perms);
  for (unsigned int i = 0; i < app_perms->psid_num; i++) {
    if (psid == app_perms->psid[i]) {
      psid_match = true;
      break;
    }
  }
  return psid_match;
}


/**
 * @brief 가용한 sequential CMH 정보를 가져온다.
 * @param[in] psid PSID
 * @param[in] now 가용 여부를 판단하기 위한 시점
 * @param[out] cert_h 가용 CMH 내에 저장되어 있는 인증서 해시가 복사될 버퍼 포인터
 * @param[out] eck_priv_key 가용 CMH 내에 저장되어 있는 개인키가 복사될 구조체 포인터 (사용 후 free()해 주어야 한다)
 * @param[out] asn1_cert 가용 CMH 내에 저장되어 있는 인증서 asn.1 정보가 복사될 구조체 포인터 (사용 후 free()해 주어야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * cert_h, eck_priv_key, asn1_cert는 모두 CMH 내에 저장되어 있는 원본 정보로부터 복사된 정보이다. (참조가 아닌)
 * 따라서, 원본 정보와 독립적으로 사용할 수 있다.
 */
int INTERNAL dot2_GetAvailableSequentialCMHInfo(
  Dot2PSID psid,
  Dot2Time64 now,
  struct Dot2SHA256 *cert_h,
  EC_KEY **eck_priv_key,
  void **asn1_cert)
{
  Log(kDot2LogLevel_Event, "Get available sequential CMH info (PSID: %u, now: "PRIu64"\n", psid, now);

  struct Dot2SequentialCMHList *list = &(g_dot2_mib.cmh_table.app);

  /*
   * 현 시점에 가용한 CMH 엔트리를 찾는다.
   */
  struct Dot2SequentialCMHEntry *cmh_entry = dot2_GetCurrentlyAvailableSequentialCMHEntry(list, now);
  if (cmh_entry == NULL) {
    return -kDot2Result_SPDU_NoAvailableCMH;
  }

  /*
   * CMH 내에 일치하는 PSID가 존재하는지 확인한다.
   */
  if (dot2_CheckSequentialCMHEntry_PSID(cmh_entry, psid) == false) {
    Err("Fail to get available sequential CMH info - no matched PSID\n");
    return -kDot2Result_SPDU_NoAvailableCMH;
  }

  /*
   * CMH 정보를 복사/반환한다.
   */
  memcpy(cert_h->octs, cmh_entry->cert_h.octs, DOT2_SHA_256_LEN);
  *eck_priv_key = EC_KEY_dup(cmh_entry->info.eck_priv_key);
  if (*eck_priv_key == NULL) {
    Err("Fail to get available sequential CMH info - EC_KEY_dup() failed\n");
    return -kDot2Result_SPDU_CopyCMHECKEY;
  }
#if defined(_FFASN1C_)
  *asn1_cert = asn1_clone_value(asn1_type_dot2Certificate, cmh_entry->asn1_cert);
#elif defined(_OBJASN1C_)
  *asn1_cert = cmh_entry->asn1_cert;
#else
#error "3rd party asn.1 library is not defined"
#endif
  if (*asn1_cert == NULL) {
    Err("Fail to get available sequential CMH info - asn1_cert copy failed\n");
    EC_KEY_free(*eck_priv_key);
    return -kDot2Result_SPDU_CopyCMHAsn1Cert;
  }

  Log(kDot2LogLevel_Event, "Success to get available sequential CMH info\n");
  return kDot2Result_Success;
}


/**
 * @brief 만기된 Sequential CMH를 리스트에서 제거한다.
 * @param[in] exp 기준이 되는 만기시각
 * @param[in] list Sequential CMH 리스트
 */
void INTERNAL dot2_RemoveExpiredSequentialCMH(Dot2Time64 exp, struct Dot2SequentialCMHList *list)
{
  Log(kDot2LogLevel_Event, "Remove expired sequentail CMH - exp: %"PRIu64"\n", exp);
  struct Dot2SequentialCMHEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(list->head), entries, tmp) {
    if (entry->info.cert_contents.common.valid_end < exp) {
      TAILQ_REMOVE(&(list->head), entry, entries);
      dot2_ClearSequentialCMHEntry(entry);
      if (entry == list->active_cmh) {
        list->active_cmh = NULL;
      }
      list->entry_num--;
      free(entry);
    }
  }
}
