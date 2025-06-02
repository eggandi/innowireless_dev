/** 
  * @file 
  * @brief Security profile 관련 인라인 함수들을 정의한 파일
  * @date 2021-09-12 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_SEC_PROFILE_INLINE_H
#define V2X_SW_DOT2_SEC_PROFILE_INLINE_H


// 라이브러리 헤더 파일
#include "dot2-internal.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief 특정 PSID에 관련된 Security profile을 테이블에서 찾는다.
 * @param[in] psid PSID
 * @return Security profile 엔트리 포인터
 * @retval NULL: 실패
 */
static inline struct Dot2SecProfileEntry * dot2_FindSecProfile(Dot2PSID psid)
{
  struct Dot2SecProfileTable *table = &(g_dot2_mib.sec_profile_table);
  struct Dot2SecProfileEntry *entry;
  TAILQ_FOREACH(entry, &(table->head), entries) {
    if (entry->profile.psid == psid) {
      return entry;
    }
  }
  return NULL;
}


/**
 * @brief Security profile 엔트리 내 "마지막으로 인증서로 서명한 시간"을 업데이트한다.
 * @param[in] time 업데이트할 시간
 * @param[out] entry 업데이트할 엔트리
 */
static inline void dot2_UpdateSecProfile_LastCertSignTime(Dot2Time64 time, struct Dot2SecProfileEntry *entry)
{
  entry->last_cert_sign_time = time;
}


/**
 * @brief Security profile에 저장된 서명 형식을 가져온다.
 * @param[in] entry Security profile 엔트리
 * @return 서명 형식
 */
static inline Dot2ECPointForm dot2_GetSecProfile_SignForm(struct Dot2SecProfileEntry *entry)
{
  Dot2ECPointForm ret;
  switch (entry->profile.tx.sign_type) {
    case kDot2SecProfileSign_X_only:
      ret = kDot2ECPointForm_X_only;
      break;
    case kDot2SecProfileSign_Uncompressed:
      ret = kDot2ECPointForm_Uncompressed;
      break;
    default: // X-only나 Uncompressed가 아니면 모두 Compressed로 서명한다.
      ret = kDot2ECPointForm_Compressed;
      break;
  }
  return ret;
}


#ifdef __cplusplus
}
#endif


#endif //V2X_SW_DOT2_SEC_PROFILE_INLINE_H
