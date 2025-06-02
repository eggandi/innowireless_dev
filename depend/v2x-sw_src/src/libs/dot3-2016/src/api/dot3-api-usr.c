/**
 * @file
 * @brief USR(User Service Request) 관련 API들을 구현한 파일
 * @date 2020-07-19
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief USR을 등록한다(상세 내용 API 매뉴얼 참조).
 * @param[in] USR 저장소에 등록할 USR 정보
 * @retval 1 이상: (USR 추가 후) 현재 등록되어 있는 USR의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_AddUSR(const struct Dot3USR *usr)
{
  Log(kDot3LogLevel_Event, "Add USR\n");

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (usr == NULL) {
    Err("Fail to add USR - null parameter\n");
    return -kDot3Result_NullParameters;
  }
  if (dot3_IsValidPSID(usr->psid) == false) {
    Err("Fail to add USR - invalid psid %u\n", usr->psid);
    return -kDot3Result_InvalidPSID;
  }
  if (dot3_IsValidWSAType(usr->wsa_type) == false) {
    Err("Fail to add USR - invalid wsa type %u\n", usr->wsa_type);
    return -kDot3Result_InvalidWSAType;
  }
  if ((usr->present.psc == true) &&
      (dot3_IsValidPSCLen(usr->psc.len) == false)) {
    Err("Fail to add USR - invalid psc len %u\n", usr->psc.len);
    return -kDot3Result_InvalidPSCLen;
  }
  if ((usr->present.advertiser_id == true) &&
      (dot3_IsValidWSAAdvertiserIDLen(usr->advertiser_id.len) == false)) {
    Err("Fail to add USR - invalid advertiser id len %u\n", usr->advertiser_id.len);
    return -kDot3Result_InvalidAdvertiserIDLen;
  }
  if ((usr->present.chan_num == true) &&
      (dot3_IsValidChannelNumber(usr->chan_num) == false)) {
    Err("Fail to add USR - invalid channel %d\n", usr->chan_num);
    return -kDot3Result_InvalidChannelNumber;
  }

  /*
   * USR을 테이블에 추가한다.
   */
  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  int ret = dot3_AddUSR(&(uinfo->usr_table), usr);
  pthread_mutex_unlock(&(uinfo->mtx));
  return ret;
}


/**
 * @brief 특정 USR을 삭제한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 삭제하고자 하는 USR의 PSID
 * @retval 0 이상: (USR 삭제 후) 현재 등로되어 있는 USR의 개수
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_DeleteUSR(Dot3PSID psid)
{
  Log(kDot3LogLevel_Event, "Delete USR (psid: %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   */
  if (dot3_IsValidPSID(psid) == false) {
    Err("Fail to delete USR - invalid psid %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * USR을 테이블에서 삭제한다.
   */
  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  int ret = dot3_DeleteUSR(&(uinfo->usr_table), psid);
  pthread_mutex_unlock(&(uinfo->mtx));
  return ret;
}


/**
 * @brief 모든 USR들을 삭제한다(상세 내용 API 매뉴얼 참조).
 */
void OPEN_API Dot3_DeleteAllUSRs(void)
{
  Log(kDot3LogLevel_Event, "Delete all USRs\n");
  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  dot3_DeleteAllUSRs(&(uinfo->usr_table));
  pthread_mutex_unlock(&(uinfo->mtx));
}


/**
 * @brief 특정 PSID를 갖는 USR 정보를 확인한다(상세 내용 API 매뉴얼 참조).
 * @param[in] psid 확인하고자 하는 USR의 PSID
 * @param[out] usr USR 정보가 반환될 변수의 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int OPEN_API Dot3_GetUSRWithPSID(Dot3PSID psid, struct Dot3USR *usr)
{
  Log(kDot3LogLevel_Event, "Get USR (psid %u)\n", psid);

  /*
   * 파라미터 유효성을 체크한다.
   *  - 널 파라미터
   *  - PSID
   */
  if (usr == NULL) {
    Err("Fail to get USR - null parameters\n");
    return -kDot3Result_NullParameters;
  }
  if (dot3_IsValidPSID(psid) == false) {
    Err("Fail to get USR - invalid psid %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * USR을 확인하여 반환한다.
   */
  struct Dot3UserInfo *uinfo = &(g_dot3_mib.user_info);
  pthread_mutex_lock(&(uinfo->mtx));
  int ret = dot3_GetUSRWithPSID(&(uinfo->usr_table), psid, usr);
  pthread_mutex_unlock(&(uinfo->mtx));
  return ret;
}


/**
 * @brief 등록되어 있는 USR의 개수를 확인한다(상세 내용 API 매뉴얼 참조).
 * @return 등록되어 있는 USR의 개수
 */
Dot3USRNum OPEN_API Dot3_GetUSRNum(void)
{
  return dot3_GetUSRNum(&(g_dot3_mib.user_info.usr_table));
}
