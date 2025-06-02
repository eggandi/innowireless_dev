/** 
 * @file
 * @brief CMH(Crypto Material Handle) 관련 구현
 * @date 2020-03-20
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cmh/dot2-cmh.h"


/**
 * @brief CMH 테이블을 초기화한다.
 */
void INTERNAL dot2_InitCMHTable(void)
{
  Log(kDot2LogLevel_Event, "Initialize CMH table\n");
  memset(&(g_dot2_mib.cmh_table), 0, sizeof(struct Dot2CMHTable));
  dot2_InitSequentialCMHList(&(g_dot2_mib.cmh_table.app));
  dot2_InitRotateCMHSetList(&(g_dot2_mib.cmh_table.pseudonym_id));
  dot2_InitSequentialCMHList(&(g_dot2_mib.cmh_table.enrol));
}


/**
 * @brief CMH 테이블을 해제한다.
 */
void INTERNAL dot2_ReleaseCMHTable(void)
{
  Log(kDot2LogLevel_Event, "Release CMH table\n");
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  struct Dot2CMHTable *table = &(g_dot2_mib.cmh_table);
  if (table->cmh_type == kDot2CMHType_Application) {
    dot2_ReleaseSequentialCMHList(&(table->app));
  } else if ((table->cmh_type == kDot2CMHType_Pseudonym) ||
             (table->cmh_type == kDot2CMHType_Identification)) {
    dot2_ReleaseRotateCMHSetList(&(table->pseudonym_id));
  }
  table->cmh_type = kDot2CMHType_Undefined;
  dot2_ReleaseSequentialCMHList(&(table->enrol));
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
}


/**
 * @brief 가용한 CMH 정보를 가져온다.
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
int INTERNAL dot2_GetAvailableCMHInfo(
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
  Log(kDot2LogLevel_Event, "Get available CMH info\n");

  int ret;
  Dot2CMHType cmh_type = g_dot2_mib.cmh_table.cmh_type;
  if (cmh_type == kDot2CMHType_Application) {
    ret = dot2_GetAvailableSequentialCMHInfo(psid, now, cert_h, eck_priv_key, asn1_cert);
  } else if ((cmh_type == kDot2CMHType_Pseudonym) ||
             (cmh_type == kDot2CMHType_Identification)) {
    ret = dot2_GetAvailableRotateCMHInfo(psid,
                                         now,
                                         interval,
                                         cmh_change,
                                         cert_h,
                                         eck_priv_key,
                                         asn1_cert,
                                         cmh_changed,
                                         cmh_expiry);
  } else {
    Err("Fail to get available CMH info - cmh type(%u) is not defined\n", cmh_type);
    ret = -kDot2Result_SPDU_UndefinedCMHType;
  }
  return ret;
}


/**
 * @brief 만기된 CMH를 삭제한다.
 * @param[in] exp 기준이 되는 만기시각
 */
void INTERNAL dot2_RemoveExpiredCMH(Dot2Time64 exp)
{
  struct Dot2CMHTable *cmh_table = &(g_dot2_mib.cmh_table);
  dot2_RemoveExpiredSequentialCMH(exp, &(cmh_table->app));
  dot2_RemoveExpiredRotateCMHSet(exp, &(cmh_table->pseudonym_id));
  dot2_RemoveExpiredSequentialCMH(exp, &(cmh_table->enrol));
}
