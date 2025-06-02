/** 
  * @file 
  * @brief 난수생성 기능에 관련된 단위테스트를 구현한 파일
  * @date 2021-09-15 
  * @author gyun 
  */

// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// google test 헤더 파일
#include "gtest/gtest.h"


/**
 * @brief 난수생성기를 이용한 난수 생성이 성공적으로 수행되는 것을 확인한다.
 */
TEST(RANDOM_NUMBER_GENERATOR, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
   * 난수생성기를 이용한 난수 생성이 성공하는 것을 확인한다.
   * 난수생성기를 이용한 난수 생성이 실패할 경우, random() 함수를 이용하여 소프트웨어적으로 생성이 되기 때문에,
   * 실제로 난수생성기가 이용되었는지 확인할 수는 없다.
   * 따라서 본 테스트는 코드 커버리지 테스트용으로 사용되고, 문제없이 실행되었는지만 확인한다.
   */
  uint8_t rn = dot2_GetRandomOct("/dev/urandom");

  /*
   * 유효하지 않은 난수생성기 이름을 전달했을 때에도 random() 함수를 이용하여 난수가 생성되는 것을 확인한다.
   * 생성된 난수가 정확한지는 알 수 없다.
   * 따라서 본 테스트는 코드 커버리지 테스트용으로 사용되고, 문제없이 실행되었는지만 확인한다.
   */
  rn = dot2_GetRandomOct("/dev/dom");

  /*
   * NULL로 전달했을 때에도 random() 함수를 이용하여 난수가 생성되는 것을 확인한다.
   * 생성된 난수가 정확한지는 알 수 없다.
   * 따라서 본 테스트는 코드 커버리지 테스트용으로 사용되고, 문제없이 실행되었는지만 확인한다.
   */
  rn = dot2_GetRandomOct(nullptr);

  Dot2_Release();
}

