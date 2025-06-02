/** 
 * @file
 * @brief Dot3_AddWSR() API에 대한 단위테스트 구현 파일
 * @date 2020-07-14
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_DeleteWSR() API 호출 시 등록되어 있는 PSID를 전달하면, WSR이 정상적으로 삭제되는 것을 확인한다.
 */
TEST(Dot3_DeleteWSR, REGISTERED_PSID)
{
  InitTestEnv();

  Dot3PSID psid = kDot3PSID_Min;
  Dot3WSRNum wsr_num = 0;

  /*
   * WSR을 등록한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_AddWSR(psid), ++wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);
  ASSERT_EQ(Dot3_CheckWSRWithPSID(psid), kDot3Result_Success);

  /*
   * 동일한 PSID를 전달하면, WSR이 정상적으로 삭제되는 것을 확인한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_DeleteWSR(psid), --wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);
  ASSERT_EQ(Dot3_CheckWSRWithPSID(psid), -kDot3Result_NoSuchWSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_DeleteWSR() API 호출 시 유효하지 않은 PSID를 전달하면, 실패하는 것을 확인한다.
 */
TEST(Dot3_DeleteWSR, INVALID_PSID)
{
  InitTestEnv();

  /*
   * 유효하지 않은 PSID를 사용하여 삭제 시도 시, 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_DeleteWSR(kDot3PSID_Max + 1), -kDot3Result_InvalidPSID);
  ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)0);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_DeleteWSR() API 호출 시 등록되어 있지 않은 PSID를 전달하면, 실패하는 것을 확인한다.
 */
TEST(Dot3_DeleteWSR, NOT_REGISTERED_PSID)
{
  InitTestEnv();

  Dot3PSID psid = kDot3PSID_Min;

  /*
   * 등록되어 있지 않은 PSID를 사용하여 삭제 시도 시, 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_DeleteWSR(psid), -kDot3Result_NoSuchWSR);
  ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)0);

  ReleaseTestEnv();
}

