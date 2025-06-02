/**
 * @file
 * @brief Security profile 관련 API 구현 파일
 * @date 2020-05-26
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief 특정 PSID에 대한 Security profile을 등록한다(상세 내용 API 매뉴얼 참조).
 * @param[in] profile 등록할 security profile
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int OPEN_API Dot2_AddSecProfile(const struct Dot2SecProfile *profile)
{
  /*
   * 파라미터 유효성을 체크한다.
   */
  if (profile == NULL) {
    Err("Fail to add security profile - null parameter\n");
    return -kDot2Result_SECPROFILE_NullParameters;
  }
  int ret = dot2_CheckSecProfile(profile);
  if (ret < 0) {
    return ret;
  }

  /*
   * Security profile을 등록한다.
   */
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  ret = dot2_AddSecProfile(profile);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  return ret;
}
