/** 
 * @file
 * @brief Dot3_DeleteAllWSRs() API에 대한 단위테스트 구현 파일
 * @date 2020-07-14
 * @author gyun
 */

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_DeleteAllWSRs() API 호출 시 정상 동작하는 것을 확인한다.
 */
TEST(Dot3_DeleteAllWSRs, NORMAL)
{
  InitTestEnv();

  /*
   * 최대 개수만큼 WSR을 등록한다.
   */
  Dot3PSID psid = kDot3PSID_Min;
  for (int i = 0; i < kDot3WSRNum_Max; i++) {
    ASSERT_EQ(Dot3_AddWSR(psid++), i + 1);
    ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)(i + 1));
  }

  /*
   * API 호출 시 정상적으로 삭제되는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetWSRNum(), kDot3WSRNum_Max);
  Dot3_DeleteAllWSRs();
  ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)0);

  ReleaseTestEnv();
}


/**
 * @brief WSR이 등록되어 있지 않은 상태에서 Dot3_DeleteAllWSRs() API 호출 시 정상 동작하는 것을 확인한다.
 */
TEST(Dot3_DeleteAllWSRs, NO_WSR)
{
  InitTestEnv();

  /*
   * API 호출 시 오류가 발생하지 않는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)0);
  Dot3_DeleteAllWSRs();
  ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)0);

  ReleaseTestEnv();
}
