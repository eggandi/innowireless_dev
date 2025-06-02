/**
 * @file
 * @brief PSR(Provider Service Request) 관련 API들을 구현한 파일
 * @date 2019-08-16
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief PSR을 등록한다(상세 내용 API 매뉴얼 참조).
 * @param[in] PSR 저장소에 등록할 PSR 정보
 * @retval 1 이상: (PSR 추가 후) 현재 등록되어 있는 PSR의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_AddPSR(const struct Dot3PSR *psr)
{
  Log(kDot3LogLevel_Event, "Add PSR\n");

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (psr == NULL) {
    Err("Fail to add PSR - null parameter\n");
    return -kDot3Result_NullParameters;
  }
  if (dot3_IsValidWSAIdentifier(psr->wsa_id) == false) {
    Err("Fail to add PSR - invalid wsa id %u\n", psr->wsa_id);
    return -kDot3Result_InvalidWSAIdentifier;
  }
  if(dot3_IsValidPSID(psr->psid) == false) {
    Err("Fail to add PSR - invalid psid %u\n", psr->psid);
    return -kDot3Result_InvalidPSID;
  }
  if (dot3_IsValidChannelNumber(psr->service_chan_num) == false) {
    Err("Fail to add PSR - invalid service channel %d\n", psr->service_chan_num);
    return -kDot3Result_InvalidChannelNumber;
  }
  if ((psr->present.psc == true) && (dot3_IsValidPSCLen(psr->psc.len) == false)) {
    Err("Fail to add PSR - invalid psc len %u\n", psr->psc.len);
    return -kDot3Result_InvalidPSCLen;
  }
  if ((psr->present.rcpi_threshold == true) && (dot3_IsValidRCPI(psr->rcpi_threshold) == false)) {
    Err("Fail to add PSR - invalid RCPI threshold %u\n", psr->rcpi_threshold);
    return -kDot3Result_InvalidWSARCPIThreshold;
  }
  if ((psr->present.wsa_cnt_threshold == true) &&
      (dot3_IsValidWSACountThreshold(psr->wsa_cnt_threshold) == false)) {
    Err("Fail to add PSR - invalid wsa_cnt_threshold %u\n", psr->wsa_cnt_threshold);
    return -kDot3Result_InvalidWSACountThreshold;
  }
  if ((psr->present.wsa_cnt_threshold_interval == true) &&
    (dot3_IsValidWSACountThresholdInterval(psr->wsa_cnt_threshold_interval) == false)) {
    Err("Fail to add PSR - invalid wsa_cnt_threshold_interval %u\n", psr->wsa_cnt_threshold_interval);
    return -kDot3Result_InvalidWSACountThresholdInterval;
  }

  /*
   * PSR을 테이블에 추가한다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  int ret = dot3_AddPSR(&(pinfo->psr_table), psr);
  pthread_mutex_unlock(&(pinfo->mtx));
  return ret;
}


/**
 * @brief 특정 PSR을 삭제한다(상세 내용 API 매뉴얼 참조).
 *
 * @param[in] psid 삭제하고자 하는 PSR의 PSID
 * @retval 0 이상: (PSR 삭제 후) 현재 등록되어 있는 PSR의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_DeletePSR(Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Delete PSR (psid: %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if(dot3_IsValidPSID(psid) == false) {
    Err("Fail to delete PSR - invalid psid %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * PSR을 테이블에서 삭제한다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  int ret = dot3_DeletePSR(&(pinfo->psr_table), psid);
  pthread_mutex_unlock(&(pinfo->mtx));
  return ret;
}


/**
 * @brief 특정 PSR의 내용을 변경한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 변경하고자 하는 PSR의 PSID
 * @param[in] psc 변경할 PSC
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_ChangePSR(Dot3PSID psid, const char *psc)
{
  Log(kDot3LogLevel_Event, "Change PSR (psid %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidPSID(psid) == false) {
    Err("Fail to change PSR - invalid psid %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }
  if (psc == NULL) {
    Err("Fail to change PSR - null parameters - psc: %p\n", psc);
    return -kDot3Result_NullParameters;
  }
  if (strlen(psc) > kDot3PSCLen_Max) {
    Err("Fail to change PSR - too long psc %d > %d\n", strlen(psc), kDot3PSCLen_Max);
    return -kDot3Result_InvalidPSCLen;
  }

  /*
   * PSR을 변경한다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  int ret = dot3_ChangePSR(&(pinfo->psr_table), psid, psc);
  pthread_mutex_unlock(&(pinfo->mtx));
  return ret;
}


/**
 * @brief 모든 PSR들을 삭제한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot3_DeleteAllPSRs(void)
{
  Log(kDot3LogLevel_Event, "Delete all PSRs\n");
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  dot3_DeleteAllPSRs(&(pinfo->psr_table));
  pthread_mutex_unlock(&(pinfo->mtx));
}


/**
 * @brief 특정 PSID를 갖는 PSR 정보를 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 확인하고자 하는 PSR의 PSID
 * @param[out] psr PSR 정보가 반환될 변수의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_GetPSRWithPSID(Dot3PSID psid, struct Dot3PSR *psr)
{
  Log(kDot3LogLevel_Event, "Get PSR (psid %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   *  - PSID
   */
  if (psr == NULL) {
    Err("Fail to get PSR - null parameters\n");
    return -kDot3Result_NullParameters;
  }
  if(dot3_IsValidPSID(psid) == false) {
    Err("Fail to get PSR - invalid psid %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * PSR을 확인하여 반환한다.
   */
  struct Dot3ProviderInfo *pinfo = &(g_dot3_mib.provider_info);
  pthread_mutex_lock(&(pinfo->mtx));
  int ret = dot3_GetPSRWithPSID(&(pinfo->psr_table), psid, psr);
  pthread_mutex_unlock(&(pinfo->mtx));
  return ret;
}


/**
 * @brief 등록되어 있는 PSR의 개수를 확인한다(상세 내용 API 매뉴얼 참조).
 * @return 등록되어 있는 PSR의 개수
 */
Dot3PSRNum OPEN_API Dot3_GetPSRNum(void)
{
  return dot3_GetPSRNum(&(g_dot3_mib.provider_info.psr_table));
}
