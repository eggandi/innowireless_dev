/** 
  * @file 
  * @brief 서명 SPDU의 freshness에 관한 relevance 체크 기능 단위테스트
  * @date 2022-01-06 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief 서명 SPDU의 freshness에 대한 relevance check 시, SPDU의 생성시각이 너무 과거일 경우의 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU_RELEVANCE_CHECK_FRESHNESS, CHECK_FRESHNESS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = true; // SPDU freshness 조건을 체크하도록 한다.
  profile.rx.relevance_check.validity_period = 100000ULL; // 수신시점에 비해 SPDU 생성시각이 100msec 보다 더 과거이면 필터링
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * [TEST] SPDU의 수신시각이 {생성시각 + 유효범위}보다 크면(SPDU 생성시점이 너무 과거이면), "실패"가 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data;
    size_t spdu_size = g_sample_max_header_signed_data_size;
    struct Dot2SPDUProcessParams params = {g_sample_max_header_signed_data_gen_time + 100000ULL + 1ULL, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 실패인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDURelevance_TooOld);
  }

  /*
   * [TEST] SPDU의 수신시각이 {생성시각 + 유효범위}와 같으면(SPDU 생성시점이 허용될만한 과거이면), "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data;
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {g_sample_max_header_signed_data_gen_time + 100000ULL, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[1].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_TRUE(g_callbacks.entry[1].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[1].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * [TEST] SPDU의 수신시각이 {생성시각 + 유효범위}보다 작으면(SPDU 생성시점이 허용될만한 과거이면), "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data;
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {g_sample_max_header_signed_data_gen_time + 100000ULL - 1ULL, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 3U);
    ASSERT_EQ(g_callbacks.entry[2].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_TRUE(g_callbacks.entry[2].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[2].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * [TEST] SPDU 내에 생성시각이 존재하지 않는 경우, 무조건 "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_min_header_signed_data;
    size_t spdu_size = g_sample_min_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {g_sample_max_header_signed_data_gen_time + 100000ULL + 1ULL, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 4U);
    ASSERT_EQ(g_callbacks.entry[3].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
    ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
    ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[3].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[3].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[3].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief 서명 SPDU의 freshness에 대한 relevance check 미 수행 시, SPDU의 생성시각이 너무 과거일 경우의 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU_RELEVANCE_CHECK_FRESHNESS, NOT_CHECK_FRESHNESS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false; // SPDU freshness 조건을 체크하지 않도록 한다.
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * [TEST] Security profile이 Freshness check를 수행하지 않도록 설정되어 있는 경우, 생성시각이 매우 과거여도 "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data;
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {g_sample_max_header_signed_data_gen_time + 100000ULL + 1ULL, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief 서명 SPDU를 검증하지 않도록 설정 시, SPDU의 생성시각이 너무 과거일 경우의 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU_RELEVANCE_CHECK_FRESHNESS, NOT_VERIFY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = false; // 서명 SPDU를 검증하지 않도록 설정한다.
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = true; // SPDU freshness 조건을 체크하도록 한다.
  profile.rx.relevance_check.validity_period = 100000ULL; // 수신시점에 비해 SPDU 생성시각이 100msec 보다 더 과거이면 필터링
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * [TEST] 생성시각이 매우 과거여도 "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data;
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {g_sample_max_header_signed_data_gen_time + 100000ULL + 1ULL, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}
