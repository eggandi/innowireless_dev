/**
  * @file
  * @brief Dot2_ConvertSystemTimeToTime32() API 단위테스트 파일
  * @date 2023-02-23
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_ConvertSystemTimeToTime32() API의 기본 동작을 확인한다.
 */
TEST(API_Dot2_ConvertSystemTimeToTime32, NORMAL)
{
  Dot2LeapSeconds leap_secs = kDot2LeapSeconds_Default;
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", leap_secs), kDot2Result_Success);

  time_t systime;
  Dot2Time32 time32;

  /*
   * 시스템시간이 2004-01-01 이후일 때 정상적으로 변환되는 것을 확인한다.
   */
  systime = 2222222222;
  time32 = (Dot2Time32)systime - 1072915200ULL + leap_secs;
  ASSERT_EQ(Dot2_ConvertSystemTimeToTime32(systime), time32);

  /*
   * 시스템시간이 2004-01-01 이전일 때 0으로 변환되는 것을 확인한다.
   */
  systime = 1070000000ULL;
  ASSERT_EQ(Dot2_ConvertSystemTimeToTime32(systime), 0U);

  Dot2_Release();
}

