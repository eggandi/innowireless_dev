/** 
  * @file 
  * @brief UnsecuredData 유형의 SPDU에 대한 Dot2_ProcessSPDU() API 동작 단위테스트 구현 파일
  * @date 2021-06-22 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 기본 UnsecureData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, SUCCESS_WHEN_SIMPLE_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * spdu 인자로 기본 UnsecuredData 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_simple_unsecured_msg;
    size_t spdu_size = g_simple_unsecured_msg_size;
    uint8_t *payload = g_simple_unsecured_payload;
    size_t payload_size = g_simple_unsecured_payload_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_UnsecuredData);
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr);
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size));
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 최소 길이 UnsecureData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, SUCCESS_WHEN_SHROTEST_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * 최소길이 UnsecureData(페이로드길이가 0인) 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_shortest_unsecured_msg; // Ieee1609Dot2Data 형식 상 가장 짧은 SPDU
    size_t spdu_size = g_shortest_unsecured_msg_size;
    uint8_t *payload = nullptr;
    size_t payload_size = 0;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_UnsecuredData);
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu == payload);
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size);
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 최대 길이 UnsecureData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, SUCCESS_WHEN_LONGEST_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * 최대길이(kDot2SPDUSize_Max) UnsecureData 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_longest_unsecured_msg; // libdot2가 지원하는 가장 긴 SPDU
    size_t spdu_size = g_longest_unsecured_msg_size;
    uint8_t *payload = g_longest_unsecured_payload;
    size_t payload_size = g_longest_unsecured_payload_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_UnsecuredData);
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr);
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size));
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 잘못된 프로토콜버전을 갖는 UnsecuredData를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_INVALID_PROTOCOL_VERSION)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * spdu 인자로 잘못된 프로토콜버전을 갖는 UnsecuredData 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_invalid_proto_ver_unsecured_msg; // 잘못된 프로토콜 버전을 갖는 SPDU
    size_t spdu_size = g_invalid_proto_ver_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 프로토콜버전 에러를 나타내는지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_InvalidProtocolVersion);
}

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 비정상 UnsecuredData를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_ABNORMAL_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * spdu 인자로 비정상 UnsecuredData 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_simple_unsecured_msg + 1; // 비정상 데이터로 변경
    size_t spdu_size = g_simple_unsecured_msg_size - 1; // 비정상 데이터로 변경
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 관련 에러를 나타내는지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDU_DecodeSPDU);
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 유효하지 않은 PSID를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_INVALID_PSID)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * 유효하지 않은 PSID를 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_simple_unsecured_msg;
    size_t spdu_size = g_simple_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, kDot2PSID_Max + 1, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidPSID);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 유효하지 않은 좌표를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_INVALID_LOCATION)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * 유효하지 않은 위도를 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_simple_unsecured_msg;
    size_t spdu_size = g_simple_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, 32, kDot2Latitude_Min - 1, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidPosition);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.

    // API 호출 실패 확인
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    spdu = g_simple_unsecured_msg;
    spdu_size = g_simple_unsecured_msg_size;
    params.rx_pos.lat = kDot2Latitude_Unavailable + 1;
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidPosition);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 유효하지 않은 경도를 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_simple_unsecured_msg;
    size_t spdu_size = g_simple_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, kDot2Longitude_Min - 1};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidPosition);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.

    // API 호출 실패 확인
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    spdu = g_simple_unsecured_msg;
    spdu_size = g_simple_unsecured_msg_size;
    params.rx_pos.lon = kDot2Longitude_Unavailable + 1;
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidPosition);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 params 인자로 NULL로 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_NULL_PARAMS)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * params 인자로 NULL로 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_simple_unsecured_msg;
    size_t spdu_size = g_simple_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, nullptr, parsed), -kDot2Result_SPDU_NullParameters);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 NULL로 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_NULL_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * spdu 인자로 NULL로 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = nullptr; // Null SPDU
    size_t spdu_size = g_simple_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_NullParameters);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 parsed 인자로 NULL로 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_NULL_PARSED)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * parsed 인자로 NULL로 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    uint8_t *spdu = g_simple_unsecured_msg;
    size_t spdu_size = g_simple_unsecured_msg_size;
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, nullptr), -kDot2Result_SPDU_NullParameters);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu_size 인자로 너무 짧은 길이를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_TOO_SHORT_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * spdu_size 인자로 너무 짧은 길이를 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_shortest_unsecured_msg;
    size_t spdu_size = g_shortest_unsecured_msg_size - 1; // Ieee1609Dot2Data 형식 상의 최소 길이보다 작게 설정
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidSPDUSize);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu_size 인자로 너무 긴 길이를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU__UnsecuredData, FAIL_WHEN_TOO_LONG_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * SCC 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * spdu_size 인자로 너무 긴 길이를 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_longest_unsecured_msg;
    size_t spdu_size = g_longest_unsecured_msg_size + 1; // libdot2가 지원하는 최대 길이보다 크게 설정
    struct Dot2SPDUProcessParams params = {0, 32, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_InvalidSPDUSize);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}
