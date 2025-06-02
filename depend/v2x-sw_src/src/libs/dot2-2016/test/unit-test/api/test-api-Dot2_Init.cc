/** 
  * @file 
  * @brief Dot2_Init() API에 대한 단위테스트를 구현한 파일
  * @date 2021-09-15 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_Init() API의 기본 동작을 확인한다.
 */
TEST(Dot2_Init, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_Release();
}


/**
 * @brief Dot2_Init() API의 서명파라미터 사전계산 파라미터 값에 따른 동작을 확인한다.
 */
TEST(Dot2_Init, PARAM_CHECK_SIGN_PARAMS_PRECOMUPUTE_INTERVAL)
{
  /*
   * 기본값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_NotUse, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_Release();

  /*
   * 기본값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_Release();

  /*
   * 최소값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Min, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_Release();

  /*
   * 최대값을 전달하면 성공하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Max, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_Release();

  /*
   * 유효하지 않은 값을 전달하면 성공적으로 에러 처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Min - 1, "/dev/urandom", kDot2LeapSeconds_Default), -kDot2Result_InvalidInterval);
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Max + 1, "/dev/urandom", kDot2LeapSeconds_Default), -kDot2Result_InvalidInterval);
}


/**
 * @brief Dot2_Init() API의 난수생성기 파라미터 값에 따른 동작을 확인한다.
 */
TEST(Dot2_Init, PARAM_CHECK_RNG_DEV)
{
  /*
   * 유효한 이름을 전달하면 성공하는 것을 확인한다. (현재 단위테스트용 도커 컨테이너 내에는 /dev/urandom, /dev/random 이 존재한다)
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.rng_dev.name, "/dev/urandom", strlen("/dev/urandom")));
  ASSERT_TRUE(g_dot2_mib.rng_dev.use);
  Dot2_Release();
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/random", kDot2LeapSeconds_Default), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.rng_dev.name, "/dev/random", strlen("/dev/random")));
  ASSERT_TRUE(g_dot2_mib.rng_dev.use);
  Dot2_Release();

  /*
   * 유효하지 않은 이름을 전달하면 성공적으로 에러 처리하는 것을 확인한다. (존재하지 않는 /dev/dom)
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/dom", kDot2LeapSeconds_Default), -kDot2Result_NoSuchDevice);
  // Dot2_Release();

  /*
   * 너무 긴 이름을 전달하면 성공적으로 에러 처리하는 것을 확인한다.
   */
  char rng_dev[DOT2_RANDOM_DEV_MAX_LEN + 2];
  for (unsigned int i = 0; i < sizeof(rng_dev); i++) {
    rng_dev[i] = 'a';
  }
  rng_dev[sizeof(rng_dev) - 1] = '\0';
  ASSERT_EQ(strlen(rng_dev), DOT2_RANDOM_DEV_MAX_LEN + 1);
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, rng_dev, kDot2LeapSeconds_Default), -kDot2Result_TooLongRandomNumberGeneratorName);
  // Dot2_Release();

  /*
   * NULL을 전달하면 소프트웨어 난수생성으로 설정되는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, nullptr, kDot2LeapSeconds_Default), kDot2Result_Success);
  ASSERT_FALSE(g_dot2_mib.rng_dev.use);
  Dot2_Release();
}
