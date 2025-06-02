/** 
  * @file 
  * @brief Dot2_ConstructSPDU() API를 이용한 UnsecureData 생성 기능에 대한 단위테스트 파일
  * @date 2021-12-29 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 기본 Unsecured SPDU를 정상적으로 생성하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_UnsecuredData, SIMPLE_PAYLOAD)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * 최소길이 원하는 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(&params, g_simple_unsecured_payload, g_simple_unsecured_payload_size);
  ASSERT_EQ(res.ret, (int)g_simple_unsecured_msg_size); // 생성된 SPDU의 길이를 확인
  ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
  ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, g_simple_unsecured_msg, g_simple_unsecured_msg_size)); // 생성된 SPDU 내용을 확인
  free(res.spdu);

  Dot2_Release();
}


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 최소길이(페이로드가 없는) Unsecured SPDU를 정상적으로 생성하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_UnsecuredData, SHORTEST_PAYLOAD)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * payload 파라미터를 null, payload_size 파라미터를 0으로 전달하면 페이로드가 포함되지 않은 최소길이 SPDU가 생성되는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(&params, nullptr, 0);
  ASSERT_EQ(res.ret, (int)g_shortest_unsecured_msg_size); // 생성된 SPDU의 길이를 확인
  ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
  ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, g_shortest_unsecured_msg, g_shortest_unsecured_msg_size)); // 생성된 SPDU 내용을 확인
  free(res.spdu);

  Dot2_Release();
}


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 최대길이 Unsecured SPDU를 정상적으로 생성하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_UnsecuredData, LONGEST_PAYLOAD)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * 최대길이 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(&params, g_longest_unsecured_payload, g_longest_unsecured_payload_size);
  ASSERT_EQ(res.ret, (int)g_longest_unsecured_msg_size); // 생성된 SPDU의 길이를 확인
  ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
  ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, g_longest_unsecured_msg, g_longest_unsecured_msg_size)); // 생성된 SPDU 내용을 확인
  free(res.spdu);

  Dot2_Release();
}


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 잘못된 파라미터를 전달하면 실패하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_UnsecuredData, INVALID_PARAMETERS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * params 파라미터가 null이면 실패하는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(nullptr, g_simple_unsecured_payload, g_simple_unsecured_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_NullParameters); // 실패 확인

  /*
   * payload 파라미터를 null, payload_size 파라미터를 0이 아닌 값으로 전달하면 실패가 반환되는 것을 확인한다.
   * payload 파라미터가 null이면 payload_size 파라미터는 0이어야 한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(&params, nullptr, 8);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_NullParameters); // 실패 확인

  /*
   * payload 파라미터를 null이 아닌 값, payload_size 파라미터를 0으로 전달하면 실패가 반환되는 것을 확인한다.
   * payload_size 파라미터가 0이면 payload 파라미터는 null이어야 한다.
   */
  uint8_t dummy_payload[8];
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(&params, dummy_payload, 0);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPayloadSize); // 실패 확인

  /*
   * 너무 긴 페이로드 전달 시 실패하는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Unsecured;
  res = Dot2_ConstructSPDU(&params, g_simple_unsecured_payload, kDot2SPDUSize_MaxPayload + 1);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPayloadSize); // 실패 확인

  /*
   * 잘못된 SPDU 유형 전달 시 실패하는 것을 확인한다.
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Max + 1;
  res = Dot2_ConstructSPDU(&params, g_simple_unsecured_payload, g_simple_unsecured_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidSPDUConstructType); // 실패 확인

  Dot2_Release();
}
