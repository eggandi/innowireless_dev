/** 
 * @file
 * @brief Security profile 기능 구현 파일
 * @date 2020-05-15
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "sec-profile/dot2-sec-profile.h"
#include "sec-profile/dot2-sec-profile-inline.h"


/**
 * @brief "Security profile 테이블"을 초기화한다.
 */
void INTERNAL dot2_InitSecProfileTable(void)
{
  Log(kDot2LogLevel_Init, "Initialize security profile table\n");
  struct Dot2SecProfileTable *table = &(g_dot2_mib.sec_profile_table);
  memset(table, 0, sizeof(struct Dot2SecProfileTable));
  TAILQ_INIT(&(table->head));
  table->max_entry_num = kDot2SecProfileEntryNum_Max;
}


/**
 * @brief Security profile 엔트리를 테이블에서 제거한다.
 * @param[in] entry 제거할 Security profile 엔트리
 */
static inline void dot2_RemoveSecProfileEntry(struct Dot2SecProfileEntry *entry)
{
  struct Dot2SecProfileTable *table = &(g_dot2_mib.sec_profile_table);
  TAILQ_REMOVE(&(table->head), entry, entries);
  dot2_FlushSecProfileReplayCheckList(&(entry->replay_check_list));
  free(entry);
  table->entry_num--;
}


/**
 * @brief "Security profile 테이블"을 비운다.
 */
void INTERNAL dot2_FlushSecProfileTable(void)
{
  Log(kDot2LogLevel_Event, "Flush security profile table\n");
  struct Dot2SecProfileTable *table = &(g_dot2_mib.sec_profile_table);
  struct Dot2SecProfileEntry *entry, *tmp;
  TAILQ_FOREACH_SAFE(entry, &(table->head), entries, tmp) {
    dot2_RemoveSecProfileEntry(entry);
  }
  table->entry_num = 0;
}


/**
 * @brief "Security profile 테이블"을 해제한다.
 */
void INTERNAL dot2_ReleaseSecProfileTable(void)
{
  Log(kDot2LogLevel_Event, "Release security profile table\n");
  dot2_FlushSecProfileTable();
}


/**
 * @brief "Security profile 엔트리"를 생성하고 정보를 저장한다.
 * @param[in] profile 생성된 "Security profile 엔트리"에 저장될 security profile
 * @retval 생성된 Security profile 엔트리 포인터: 성공
 * @retval NULL: 실패
 */
static inline struct Dot2SecProfileEntry * dot2_MakeSecProfileEntry(const struct Dot2SecProfile *profile)
{
  struct Dot2SecProfileEntry *entry = (struct Dot2SecProfileEntry *)calloc(1, sizeof(struct Dot2SecProfileEntry));
  if (entry) {
    memcpy(&(entry->profile), profile, sizeof(struct Dot2SecProfile));
    entry->last_cert_sign_time = 0ULL;
    dot2_InitSecProfileReplayCheckList(&(entry->replay_check_list));
  }
  return entry;
}


/**
 * @brief "Security profile 엔트리"를 "Security profile 테이블"에 삽입한다.
 * @param[in] entry 삽입할 "Security profile 엔트리"
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_PushSecProfileEntry(struct Dot2SecProfileEntry *entry)
{
  /*
   * 테이블 오버플로우를 확인한다.
   */
  struct Dot2SecProfileTable *table = &(g_dot2_mib.sec_profile_table);
  if (table->entry_num >= table->max_entry_num) {
    Err("Fail to push security profile - table is full(max: %u)\n", table->max_entry_num);
    return -kDot2Result_SECPROFILE_TooManySecProfileInTable;
  }

  /*
   * 테이블의 뒤쪽에 삽입한다.
   */
  TAILQ_INSERT_TAIL(&(table->head), entry, entries);
  table->entry_num++;
  return kDot2Result_Success;
}


/**
 * @brief 송신 "Security profile"에 설정된 각 항목의 유효성을 확인한다.
 * @param[in] profile 유효성 확인할 송신 security profile
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckTxSecProfile(const struct Dot2TxSecProfile *profile)
{
  if (profile->min_inter_cert_time > kDot2SecProfileInterCertTime_Max) {
    Err("Fail to check tx security profile validity - invalid min inter cert time %llu\n", profile->min_inter_cert_time);
    return -kDot2Result_SECPROFILE_InvalidMinimumInterCertTime;
  }
  if (profile->sign_type > kDot2SecProfileSign_Max) {
    Err("Fail to check tx security profile validity - invalid sign type %u\n", profile->sign_type);
    return -kDot2Result_SECPROFILE_InvalidSignatureType;
  }
  if (profile->ecp_format > kDot2SecProfileEcPointFormat_Max) {
    Err("Fail to check tx security profile validity - invalid ecp format %u\n", profile->ecp_format);
    return -kDot2Result_SECPROFILE_InvalidECPointType;
  } else if (profile->ecp_format != kDot2SecProfileEcPointFormat_Compressed) { // 표준 상, 현재 Compressed만 지원한다.
    Err("Fail to check tx security profile validity - not supported ecp format %u\n", profile->ecp_format);
    return -kDot2Result_SECPROFILE_NotSupportedEccCurvePointType;
  }
  return kDot2Result_Success;
}


/**
 * @brief 수신 "Security profile"에 설정된 각 항목의 유효성을 확인한다.
 * @param[in] profile 유효성 확인할 수신 security profile
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_CheckRxSecProfile(const struct Dot2RxSecProfile *profile)
{
  if (profile->verify_data == true) {
    if ((profile->relevance_check.gen_time_in_past == true) ||
        (profile->relevance_check.gen_time_in_future == true)) {
      if (profile->relevance_check.gen_time_src != kDot2RelevanceTimeSource_SecurityHeader) {
        Err("Fail to check rx security profile validity - invalid generation time source: %u\n",
            profile->relevance_check.gen_time_src);
        return -kDot2Result_SECPROFILE_InvalidSPDUGenerationTimeSource;
      }
    }
    if (profile->relevance_check.exp_time == true) {
      if (profile->relevance_check.exp_time_src != kDot2RelevanceTimeSource_SecurityHeader) {
        Err("Fail to check rx security profile validity - invalid expiry time source: %u\n",
            profile->relevance_check.exp_time_src);
        return -kDot2Result_SECPROFILE_InvalidSPDUExpiryTimeSource;
      }
    }
    if (profile->relevance_check.gen_location_distance == true) {
      if (profile->relevance_check.gen_location_src != kDot2ConsistencyLocationSource_SecurityHeader) {
        Err("Fail to check rx security profile validity - invalid gen location source: %u\n",
            profile->relevance_check.gen_location_src);
        return -kDot2Result_SECPROFILE_InvalidSPDUGenerationLocationSource;
      }
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief Security profile에 설정된 각 항목의 유효성을 확인한다.
 * @param[in] profile 유효성 확인할 security profile
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_CheckSecProfile(const struct Dot2SecProfile *profile)
{
  Log(kDot2LogLevel_Event, "Check security profile\n");

  /*
   * 공통항목의 유효성을 확인한다.
   */
  if (dot2_CheckPSID(profile->psid) == false) {
    Err("Fail to check security profile validity - invalid PSID %u\n", profile->psid);
    return -kDot2Result_SECPROFILE_InvalidPSID;
  }

  /*
   * 송신항목의 유효성을 확인한다.
   */
  int ret = dot2_CheckTxSecProfile(&(profile->tx));
  if (ret < 0) {
    return ret;
  }

  /*
   * 수신항목의 유효성을 확인한다.
   */
  ret = dot2_CheckRxSecProfile(&(profile->rx));
  if (ret < 0) {
    return ret;
  }

  Log(kDot2LogLevel_Event, "Success to check security profile validity\n");
  return kDot2Result_Success;
}


/**
 * @brief 송신 Security profile의 내용을 출력한다.
 * @param[in] level 로그출력레벨
 * @param[in] profile 송신 Security profile
 */
static inline void dot2_PrintTxSecProfile(Dot2LogLevel level, const struct Dot2TxSecProfile *profile)
{
  Log(level, "Tx security profile contetns\n");
  Log(level, "  gen_time_hdr: %u, gen_location_hdr: %u, exp_time_hdr: %u\n",
      profile->gen_time_hdr, profile->gen_location_hdr, profile->exp_time_hdr);
  Log(level,
      "  spdu_lifetime: %"PRIu64"usec, min_inter_cert_time: %"PRIu64"usec, sign_type: %u, ecp_format: %u, interval: %umsec\n",
      profile->spdu_lifetime, profile->min_inter_cert_time, profile->sign_type, profile->ecp_format, profile->interval);
}


/**
 * @brief 수신 Security profile의 내용을 출력한다.
 * @param[in] level 로그출력레벨
 * @param[in] profile 수신 Security profile
 */
static inline void dot2_PrintRxSecProfile(Dot2LogLevel level, const struct Dot2RxSecProfile *profile)
{
  Log(level, "Rx security profile contetns\n");
  Log(level, "  verify_data: %u\n", profile->verify_data);
  Log(level, "  relevance - replay: %u, gen_time_in_past: %u, validity_period: %uus\n",
      profile->relevance_check.replay, profile->relevance_check.gen_time_in_past,
      profile->relevance_check.validity_period);
  Log(level, "              gen_time_in_future: %u, acceptable_future_data_period: %uus, gen_time_src: %u\n",
      profile->relevance_check.gen_time_in_future, profile->relevance_check.acceptable_future_data_period,
      profile->relevance_check.gen_time_src);
  Log(level, "              exp_time: %u, exp_time_src: %u\n",
      profile->relevance_check.exp_time, profile->relevance_check.exp_time_src);
  Log(level, "              gen_location_distance: %u, valid_distance: %um, gen_location_src: %u\n",
      profile->relevance_check.gen_location_distance, profile->relevance_check.valid_distance,
      profile->relevance_check.gen_location_src);
  Log(level, "              cert_expiry %u\n", profile->relevance_check.cert_expiry);
  Log(level, "  consistency - gen_location: %u, overdue_crl_tolerance: %us\n",
      profile->consistency_check.gen_location, profile->consistency_check.overdue_crl_tolerance);
}


/**
 * @brief Security profile의 내용을 출력한다.
 * @param[in] level 로그출력레벨
 * @param[in] profile Security profile
 */
static inline void dot2_PrintSecProfile(Dot2LogLevel level, const struct Dot2SecProfile *profile)
{
  Log(level, "Security profile contents\n");
  Log(level, "  PSID: %u\n", profile->psid);
  dot2_PrintTxSecProfile(level, &(profile->tx));
  dot2_PrintRxSecProfile(level, &(profile->rx));
}


/**
 * @brief 특정 psid에 대한 "Security profile"을 "Security profile 테이블"에 추가한다.
 * @param[in] profile 추가할 security profile
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddSecProfile(const struct Dot2SecProfile *profile)
{
  Log(kDot2LogLevel_Event, "Add security profile (PSID: %u)\n", profile->psid);
  dot2_PrintSecProfile(kDot2LogLevel_Event, profile);

  /*
   * 동일한 psid를 갖는 security profile이 이미 테이블에 존재하는지 확인한다.
   */
  struct Dot2SecProfileEntry *entry = dot2_FindSecProfile(profile->psid);
  if (entry) {
    Err("Fail to add security profile - security profile(psid: %u) already exists in table\n", entry->profile.psid);
    return -kDot2Result_SECPROFILE_SameSecProfileInTable;
  }

  /*
   * Security profile 엔트리를 생성하여 정보 저장 후 테이블에 추가한다.
   */
  int ret = -kDot2Result_NoMemory;
  entry = dot2_MakeSecProfileEntry(profile);
  if (entry) {
    ret = dot2_PushSecProfileEntry(entry);
    if (ret < 0) {
      free(entry);
    }
  }
  return ret;
}


/**
 * @brief 특정 Security profile에 대해, 현 시점에 사용될 서명자식별자 유형을 선택한다.
 * @param[in] now 현재 시각
 * @param[in/out] entry Security profile 엔트리
 * @retval kDot2SignerId_Certificate: 인증서로 서명 필요
 * @retval kDot2SignerId_Digest: 다이제스트로 서명 필요
 *
 * 가장 최근에 인증서로 서명된 시점으로부터 min inter cert time 이상 지났는지 확인하여;\n
 *  - 지난 경우, 인증서로 서명하도록 반환된다.\n
 *  - 지나지 않은 경우, 다이제스트로 서명하도록 반환된다.\n
 */
Dot2SignerIdType INTERNAL dot2_SelectSignerIdType(Dot2Time64 now, struct Dot2SecProfileEntry *entry)
{
  Log(kDot2LogLevel_Event, "Select signer id type\n");

  /*
   * 아직 인증서로 서명된 적이 없으면 인증서로 서명하도록 반환한다.
   */
  if (entry->last_cert_sign_time == 0ULL) {
    entry->last_cert_sign_time = now;
    Log(kDot2LogLevel_Event, "It's first signing. Signing time is updated to now(%"PRIu64") - return certificate\n",
        entry->last_cert_sign_time);
    return kDot2SignerId_Certificate;
  }

  /*
   * 현재 시각이 지난번 인증서 서명 시각으로부터 min inter cert time 이상 지났으면, 인증서로 서명하도록 반환한다.
   */
  if (now >= (entry->last_cert_sign_time + entry->profile.tx.min_inter_cert_time)) {
    Log(kDot2LogLevel_Event, "Current(%"PRIu64") >= previous cert sign(%"PRIu64") + min_inter_cert_time(%"PRIu64")"
        " - return certificate\n", now, entry->last_cert_sign_time, entry->profile.tx.min_inter_cert_time);
    entry->last_cert_sign_time = now;
    return kDot2SignerId_Certificate;
  }

  /*
   * 현재 시각이 지난번 인증서 서명 시각으로부터 min inter cert time 이상 지나지 않았으면, 다이제스트로 서명하도록 반환한다.
   */
  Log(kDot2LogLevel_Event, "Current(%"PRIu64") < previous cert sign(%"PRIu64") + min_inter_cert_time(%"PRIu64")"
      " - return digest\n", now, entry->last_cert_sign_time, entry->profile.tx.min_inter_cert_time);
  return kDot2SignerId_Digest;
}
