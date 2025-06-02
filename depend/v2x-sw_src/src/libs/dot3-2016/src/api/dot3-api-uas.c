/**
 * @file
 * @brief UAS(User Available Service) 관련 API들을 구현한 파일
 * @date 2020-07-25
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief 모든 UAS 정보(들)을 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return UAS 정보 집합
 * @retval NULL: 실패
 */
struct Dot3UASSet OPEN_API * Dot3_GetAllUASs(int *err)
{
  /*
   * 파라미터 유효성을 체크한다.
   */
  if (err == NULL) {
    Err("Fail to get all UASs - null parameters\n");
    return NULL;
  }

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  struct Dot3UASSet *set = dot3_GetAllUASs(&(uinfo->uas_table), err);
  pthread_mutex_unlock(&(uinfo->mtx));
  return set;
}


/**
 * @brief 특정 PSID를 갖는 UAS 정보(들)을 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 확인하고자 하는 UAS의 PSID
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return UAS 정보 집합
 * @retval NULL: 실패
 */
struct Dot3UASSet OPEN_API * Dot3_GetUASsWithPSID(Dot3PSID psid, int *err)
{
  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   *  - 잘못된 psid는 어차피 탐색 중에 걸러지기 때문에 굳이 검사하지 않는다.
   */
  if (err == NULL) {
    Err("Fail to get UASs with PSID - null err parameters\n");
    return NULL;
  }

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  struct Dot3UASSet *set = dot3_GetUASsWithPSID(&(uinfo->uas_table), psid, err);
  pthread_mutex_unlock(&(uinfo->mtx));
  return set;
}


/**
 * @brief 특정 송신지 MAC 주소를 갖는 UAS 정보(들)을 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] addr 확인하고자 하는 UAS의 송신지 MAC 주소
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return UAS 정보 집합
 * @retval NULL: 실패
 */
struct Dot3UASSet OPEN_API * Dot3_GetUASsWithSourceMACAddress(const Dot3MACAddress addr, int *err)
{
  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   */
  if (err == NULL) {
    Err("Fail to get UASs with src MAC address - null err parameters\n");
    return NULL;
  }
  if (addr == NULL) {
    Err("Fail to get UASs with src MAC address - null addr parameters\n");
    *err = -kDot3Result_NullParameters;
    return NULL;
  }

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  struct Dot3UASSet *set = dot3_GetUASsWithSourceMACAddress(&(uinfo->uas_table), addr, err);
  pthread_mutex_unlock(&(uinfo->mtx));
  return set;
}


/**
 * @brief 특정 PSID와 송신지 MAC 주소를 갖는 UAS 정보(들)을 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 확인하고자 하는 UAS의 PSID
 * @param[in] addr 확인하고자 하는 UAS의 송신지 MAC 주소
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return UAS 정보 집합
 * @retval NULL: 실패
 */
struct Dot3UASSet OPEN_API * Dot3_GetUASsWithPSIDAndSourceMACAddress(Dot3PSID psid, const Dot3MACAddress addr, int *err)
{
  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   *  - 잘못된 psid는 어차피 탐색 중에 걸러지기 때문에 굳이 검사하지 않는다.
   */
  if (err == NULL) {
    Err("Fail to get UASs with PSID and src MAC address - null err parameters\n");
    return NULL;
  }
  if (addr == NULL) {
    Err("Fail to get UASs with PSID and src MAC address - null addr parameters\n");
    *err = -kDot3Result_NullParameters;
    return NULL;
  }

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  struct Dot3UASSet *set = dot3_GetUASsWithPSIDAndSourceMACAddress(&(uinfo->uas_table), psid, addr, err);
  pthread_mutex_unlock(&(uinfo->mtx));
  return set;
}


/**
 * @brief 가장 큰 RCPI 값을 갖는 UAS 정보(들)을 반환한다(상세 내용 API 매뉴얼 참조).
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수 포인터
 * @return UAS 정보 집합
 * @retval NULL: 실패
 */
struct Dot3UASSet OPEN_API * Dot3_GetUASsWithMaxRCPI(int *err)
{
  Log(kDot3LogLevel_Event, "Get UASs with max RCPI\n");

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   */
  if (err == NULL) {
    Err("Fail to get UASs with max RCPI - null err parameters\n");
    return NULL;
  }

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  struct Dot3UASSet *set = dot3_GetUASsWithMaxRCPI(&(uinfo->uas_table), err);
  pthread_mutex_unlock(&(uinfo->mtx));
  return set;
}


/**
 * @brief 모든 UAS 정보(들)을 삭제한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot3_DeleteAllUASs(void)
{
  Log(kDot3LogLevel_Event, "Delete all UASs\n");

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  dot3_DeleteAllUASs(&(uinfo->uas_table));
  pthread_mutex_unlock(&(uinfo->mtx));
}


/**
 * @brief UAS 관리 기능을 시작한다(상세 내용 API 매뉴얼 참조).
 * @param[in] interval UAS 관리 기능이 동작하는 주기
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_StartUASManagement(Dot3UASManagementInterval interval)
{
  Log(kDot3LogLevel_Event, "Start UAS management\n");

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidUASManagementInterval(interval) == false) {
    Err("Fail to start UAS management - invalid interval: %u * 100msec\n", interval);
    return -kDot3Result_InvalidUASManagementInterval;
  }

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  int ret = dot3_StartUASManagementFunction(&(uinfo->uas_table), interval);
  pthread_mutex_unlock(&(uinfo->mtx));
  return ret;
}


/**
 * @brief UAS 관리 기능을 중지한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot3_StopUASManagement(void)
{
  Log(kDot3LogLevel_Event, "Stop UAS management\n");

  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  dot3_StopUASManagementFunction(&(uinfo->uas_table));
  pthread_mutex_unlock(&(uinfo->mtx));
}
