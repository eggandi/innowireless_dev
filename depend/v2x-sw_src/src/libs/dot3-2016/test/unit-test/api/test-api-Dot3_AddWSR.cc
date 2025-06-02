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
 * @brief Dot3_AddWSR() API 호출 시 유효한 PSID로 등록하면, WSR이 정상적으로 등록되는 것을 확인한다.
 */
TEST(Dot3_AddWSR, VALID_PSID)
{
  InitTestEnv();

  Dot3WSRNum wsr_num = 0;

  /*
   * 최소 PSID 값 전달 시 정상적으로 등록되는 것을 확인한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_AddWSR(kDot3PSID_Min), ++wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);

  /*
   * 최대 PSID 값 전달 시 정상적으로 등록되는 것을 확인한다.
   */
  ASSERT_EQ((Dot3WSRNum)Dot3_AddWSR(kDot3PSID_Max), ++wsr_num);
  ASSERT_EQ(Dot3_GetWSRNum(), wsr_num);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddWSR() API 호출 시 유효하지 않은 PSID로 등록하면, 등록이 실패하는 것을 확인한다.
 */
TEST(Dot3_AddWSR, INVALID_PSID)
{
  InitTestEnv();

  /*
   * 최대값을 초과하는 PSID 값 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddWSR(kDot3PSID_Max + 1), -kDot3Result_InvalidPSID);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddWSR() API 호출 시 테이블이 꽉 차 있으면 등록이 실패하는 것을 확인한다.
 */
TEST(Dot3_AddWSR, TABLE_FULL)
{
  InitTestEnv();

  /*
   * 최대 개수만큼 PSID를 등록하여 테이블이 꽉 차게 한다.
   */
  Dot3PSID psid = kDot3PSID_Min;
  for (int i = 0; i < kDot3WSRNum_Max; i++) {
    ASSERT_EQ(Dot3_AddWSR(psid++), i + 1);
  }
  ASSERT_EQ(Dot3_GetWSRNum(), kDot3WSRNum_Max); // 꽉 찬 것을 확인한다.

  /*
   * 추가로 등록하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddWSR(psid), -kDot3Result_WSRTableFull);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_AddWSR() API 호출 시 이미 등록되어 있는 PSID로 등록하면 등록이 실패하는 것을 확인한다.
 */
TEST(Dot3_AddWSR, TABLE_DUPLICATED_WSR)
{
  InitTestEnv();

  /*
   * 하나의 WSR을 등록한다.
   */
  Dot3PSID psid = kDot3PSID_Min;
  ASSERT_EQ(Dot3_AddWSR(psid), 1);
  ASSERT_EQ(Dot3_GetWSRNum(), (Dot3WSRNum)1);

  /*
   * 동일한 PSID로 등록을 시도하면 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot3_AddWSR(psid), -kDot3Result_DuplicatedWSR);

  ReleaseTestEnv();
}
