/**
 * @file
 * @date 2019-06-04
 * @author gyun
 * @brief dot3 라이브러리 기본 기능 구현 파일
 */


// 시스템  헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"
#include "dot3-mib.h"


/// 라이브러리 관리정보
struct Dot3MIB INTERNAL g_dot3_mib;


/// 각 ResultCode에 대한 설명문자열
const char * g_dot3_rc_str[kDot3Result_Count] = {
  "kDot3Result_Success",
  "kDot3Result_NullParameters",
  "kDot3Result_InvalidWSMPayloadSize",
  "kDot3Result_InvalidPSID",
  "kDot3Result_InvalidPSIDFormat",
  "kDot3Result_InvalidPriority",
  "kDot3Result_InvalidChannelNumber",
  "kDot3Result_InvalidDataRate",
  "kDot3Result_InvalidPower",
  "kDot3Result_InvalidOperatingClass",
  "kDot3Result_InvalidWSARCPIThreshold",
  "kDot3Result_InvalidWSACountThreshold",
  "kDot3Result_InvalidWSACountThresholdInterval",
  "kDot3Result_InvalidWSAType",
  "kDot3Result_InvalidRCPI",
  "kDot3Result_InvalidUASManagementInterval",
  "kDot3Result_InvalidChannelIndex",
  "kDot3Result_InvalidWSMPNHeaderSubType",
  "kDot3Result_InvalidWSMPNHeaderExtensionID",
  "kDot3Result_InvalidWSMPNHeaderTPID",
  "kDot3Result_InvalidWSMPNHeaderWSMPVersion",
  "kDot3Result_InvalidLowerLayerProtocolVersion",
  "kDot3Result_InvalidLowerLayerFrameType",
  "kDot3Result_InvalidWSAIdentifier",
  "kDot3Result_InvalidWSAContentCount",
  "kDot3Result_InvalidChannelAccess",
  "kDot3Result_InvalidAdvertiserIDLen",
  "kDot3Result_InvalidPSCLen",
  "kDot3Result_InvalidLatitude",
  "kDot3Result_InvalidLongitude",
  "kDot3Result_InvalidElevation",
  "kDot3Result_InvalidWSAHdrExtensionID",
  "kDot3Result_InvalidWCIExtensionID",
  "kDot3Result_InvalidWSIExtensionID",
  "kDot3Result_InvalidWSAMessage",
  "kDot3Result_InvalidWSAVersion",
  "kDot3Result_InvalidIPv6PrefixLen",
  "kDot3Result_InvalidWRARouterLifetime",
  "kDot3Result_InvalidWSMMaxLength",
  "kDot3Result_InvalidRepeatRate",
  "kDot3Result_InvalidWSMSize",
  "kDot3Result_InvalidMPDUSize",
  "kDot3Result_InvalidAIFSN",
  "kDot3Result_InvalidECWMin",
  "kDot3Result_InvalidECWMax",
  "kDot3Result_Asn1Encode",
  "kDot3Result_Asn1Decode",
  "kDot3Result_Asn1AbnormalOp",
  "kDot3Result_NotWildcardBSSID",
  "kDot3Result_NotSupportedEtherType",
  "kDot3Result_WSRTableFull",
  "kDot3Result_DuplicatedWSR",
  "kDot3Result_NoSuchWSR",
  "kDot3Result_PSRTableFull",
  "kDot3Result_DuplicatedPSR",
  "kDot3Result_NoSuchPSR",
  "kDot3Result_PCITableFull",
  "kDot3Result_NoSuchPCI",
  "kDot3Result_USRTableFull",
  "kDot3Result_DuplicatedUSR",
  "kDot3Result_NoSuchUSR",
  "kDot3Result_UASTableFull",
  "kDot3Result_AlreadyRunning",
  "kDot3Result_NoRelatedChannelInfo",
  "kDot3Result_NoMemory",
  "kDot3Result_SystemCallFailed"
};


/**
 * @brief Provider info 정보를 초기화한다.
 * @param[in] pinfo 초기화할 provider info 정보
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
static int dot3_InitProviderInfo(struct Dot3ProviderInfo *pinfo)
{
  Log(kDot3LogLevel_Init, "Initialize provider info\n");
  pthread_mutex_init(&(pinfo->mtx), NULL);

  /*
   * PSR 테이블을 초기화한다.
   */
  dot3_InitPSRTable(&(pinfo->psr_table));

  /*
   * PCI 테이블을 초기화한다.
   */
  int ret = dot3_InitPCITable(&(pinfo->pci_table));
  if (ret < 0) {
    dot3_FlushPCITable(&(pinfo->pci_table));
    return ret;
  }

  Log(kDot3LogLevel_Init, "Success to initialize provider info\n");
  return kDot3Result_Success;
}


/**
 * @brief Provider info 정보를 해제한다.
 */
static void dot3_ReleaseProviderInfo(struct Dot3ProviderInfo *pinfo)
{
  Log(kDot3LogLevel_Event, "Release provider info\n");

  pthread_mutex_lock(&(pinfo->mtx));

  /*
   * PSR 테이블을 비운다.
   */
  dot3_FlushPSRTable(&(pinfo->psr_table));

  /*
   * PCI 테이블을 비운다.
   */
  dot3_FlushPCITable(&(pinfo->pci_table));

  pthread_mutex_unlock(&(pinfo->mtx));
}


/**
 * @brief User info 정보를 초기화한다.
 * @param[in] uinfo 초기화할 user info 정보
 */
static void dot3_InitUserInfo(struct Dot3UserInfo *uinfo)
{
  Log(kDot3LogLevel_Init, "Initialize user info\n");
  pthread_mutex_init(&(uinfo->mtx), NULL);

  /*
   * USR 테이블을 초기화한다.
   */
  dot3_InitUSRTable(&(uinfo->usr_table));

  /*
   * UAS 테이블을 초기화한다.
   */
  dot3_InitUASTable(&(uinfo->uas_table));

  Log(kDot3LogLevel_Init, "Success to initialize user info\n");
}


/**
 * @brief User info 정보를 해제한다.
 */
static void dot3_ReleaseUserInfo(struct Dot3UserInfo *uinfo)
{
  Log(kDot3LogLevel_Event, "Release user info\n");

  pthread_mutex_lock(&(uinfo->mtx));

  /*
   * USR 테이블을 비운다.
   */
  dot3_FlushUSRTable(&(uinfo->usr_table));

  /*
   * UAS 관리기능을 중지한다.
   */
  dot3_StopUASManagementFunction(&(uinfo->uas_table));

  /*
   * UAS 테이블을 비운다.
   */
  dot3_FlushUASTable(&(uinfo->uas_table));

  pthread_mutex_unlock(&(uinfo->mtx));
}


/**
 * @brief dot3 라이브러리를 초기화한다.
 * @param[in] log_level 로그메시지출력레벨
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_InitDot3(Dot3LogLevel log_level)
{
  /*
   * 로그 레벨을 설정한다.
   */
  g_dot3_log = (log_level > kDot3LogLevel_Max) ? kDot3LogLevel_Max : log_level;

  Log(kDot3LogLevel_Init, "Initialize dot3 library - log level: %u\n", log_level);

  memset(&g_dot3_mib, 0, sizeof(g_dot3_mib));
  g_dot3_mib.wsm_max_len = kDot3WSMSize_Max;

  /*
   * WSR 테이블을 초기화한다.
   */
  dot3_InitWSRTable(&(g_dot3_mib.wsr_table));

  /*
   * Provider 정보를 초기화한다.
   */
  int ret = dot3_InitProviderInfo(&(g_dot3_mib.provider_info));
  if (ret < 0) {
    return ret;
  }

  /*
   * User 정보를 초기화한다.
   */
  dot3_InitUserInfo(&(g_dot3_mib.user_info));

  Log(kDot3LogLevel_Init, "Success to initialize dot3 library\n");
  return kDot3Result_Success;
}


/**
 * @brief dot3 라이브러리를 해제한다.
 */
void INTERNAL dot3_ReleaseDot3(void)
{
  Log(kDot3LogLevel_Event, "Release dot3 library\n");

  /*
   * WSR 테이블을 비운다.
   */
  struct Dot3WSRTable *wsr_table = &(g_dot3_mib.wsr_table);
  pthread_mutex_lock(&(wsr_table->mtx));
  dot3_FlushWSRTable(wsr_table);
  pthread_mutex_unlock(&(wsr_table->mtx));

  /*
   * Provider 정보를 해제한다.
   */
  dot3_ReleaseProviderInfo(&(g_dot3_mib.provider_info));

  /*
   * User 정보를 해제한다.
   */
  dot3_ReleaseUserInfo(&(g_dot3_mib.user_info));
}


/**
 * @brief EDCA Parameter Set에 담긴 정보가 유효한지 체크한다.
 * @param[in] set 체크할 EDCA Parameter Set
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_CheckEDCAParameterSet(const struct Dot3EDCAParameterSet *set)
{
  const struct Dot3EDCAParameterRecord *record;
  for (int i = 0; i < AC_NUM; i++) {
    record = &(set->record[i]);
    if (dot3_IsValidAIFSN(record->aifsn) == false) {
      return -kDot3Result_InvalidAIFSN;
    }
    if (dot3_IsValidECW(record->ecwmin) == false) {
      return -kDot3Result_InvalidECWMin;
    }
    if (dot3_IsValidECW(record->ecwmax) == false) {
      return -kDot3Result_InvalidECWMax;
    }
    if (record->ecwmax < record->ecwmin) {
      return -kDot3Result_InvalidECWMax;
    }
  }
  return kDot3Result_Success;
}
