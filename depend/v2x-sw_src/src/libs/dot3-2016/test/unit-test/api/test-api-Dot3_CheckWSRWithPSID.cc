/** 
 * @file
 * @brief Dot3_CheckWSRWithPSID() API에 대한 단위테스트 구현 파일
 * @date 2020-07-14
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_CheckWSRWithPSID() API 호출 시 등록되어 있는 PSID를 전달하면 성공하는 것을 확인한다.
 */
TEST(Dot3_CheckWSRWithPSID, REGISTERED_PSID)
{
  InitTestEnv();

  Dot3WSRNum wsr_num = 0;
  Dot3PSID psid = kDot3PSID_Min;

  /*
   * WSR을 등록한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_AddWSR(psid), ++wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);

  /*
   * API 호출 시 정상 동작하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_CheckWSRWithPSID(psid), kDot3Result_Success);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_CheckWSRWithPSID() API 호출 시 등록되어 있지 않은 PSID를 전달하면 실패하는 것을 확인한다.
 */
TEST(Dot3_CheckWSRWithPSID, NOT_REGISTERED_PSID)
{
  InitTestEnv();

  Dot3WSRNum wsr_num = 0;
  Dot3PSID psid = kDot3PSID_Min;

  /*
   * WSR을 등록한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_AddWSR(psid), ++wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);

  /*
   * API 호출 시 등록되지 않은 PSID를 전달하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_CheckWSRWithPSID(psid + 1), -kDot3Result_NoSuchWSR);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_CheckWSRWithPSID() API 호출 시 유효하지 않은 PSID를 전달하면 실패하는 것을 확인한다.
 */
TEST(Dot3_CheckWSRWithPSID, INVALID_PSID)
{
  InitTestEnv();

  Dot3WSRNum wsr_num = 0;
  Dot3PSID psid = kDot3PSID_Min;

  /*
   * WSR을 등록한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_AddWSR(psid), ++wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);

  /*
   * 유효하지 않은 PSID를 전달하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_CheckWSRWithPSID(kDot3PSID_Max + 1), -kDot3Result_InvalidPSID);

  ReleaseTestEnv();
}
