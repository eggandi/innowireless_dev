/** 
  * @file 
  * @brief 서명 SPDU의 내부 consistency 체크 기능 단위테스트
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
 * @brief 서명 SPDU에 대한 내부 consistency 체크 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU_CONSISTENCY_CHECK_INTERNAL, CHECK_INTERNAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile을 추가한다 - 테스트 및 등록성공에 필요한 최소한의 정보만 등록한다.
   */
  struct Dot2SecProfile profile;
  memset(&profile, 0, sizeof(profile));
  profile.psid = 135;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * [TEST] SPDU 내에 생성시각과 만기시각이 모두 없는 경우, "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_spdu_consistency_check_no_gentime_exptime;
    size_t spdu_size = g_sample_spdu_consistency_check_no_gentime_exptime_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * [TEST] SPDU 내에 생성시각만 존재하고 만기시각은 존재하지 않는 경우, "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_spdu_consistency_check_gentime_only;
    size_t spdu_size = g_sample_spdu_consistency_check_gentime_only_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
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
    ASSERT_FALSE(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
    ASSERT_FALSE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[1].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[1].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * [TEST] SPDU 내에 생성시각은 존재하지 않고 만기시각만 존재하는 경우, "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_spdu_consistency_check_exptime_only;
    size_t spdu_size = g_sample_spdu_consistency_check_exptime_only_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 3U);
    ASSERT_EQ(g_callbacks.entry[2].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[2].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[2].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * [TEST] SPDU 내에 생성시각/만기시각이 모두 존재하고 생성시각이 만기시각보다 과거인 경우, "성공"이 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_spdu_consistency_check_gentime_exptime;
    size_t spdu_size = g_sample_spdu_consistency_check_gentime_exptime_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 4U);
    ASSERT_EQ(g_callbacks.entry[3].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[3].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_TRUE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_TRUE(g_callbacks.entry[3].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_FALSE(g_callbacks.entry[3].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[3].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[3].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[3].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * [TEST] SDPU 내 생성시각/만기시각이 모두 존재하고 생성시각이 만기시각보다 미래인 경우, "실패"가 반환되는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_spdu_consistency_check_gentime_is_future_than_exptime;
    size_t spdu_size = g_sample_spdu_consistency_check_gentime_is_future_than_exptime_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 실패인 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 5U);
    ASSERT_EQ(g_callbacks.entry[4].result, -kDot2Result_SPDUConsistency_ExpTimeBeforeGenTimeInSPDU);
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Security Profile 등록 시 수신데이터 검증을 하지 않도록 설정(rx.verify_data=false)하면 Consistency check가 생략되는 것을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU_CONSISTENCY_CHECK_INTERNAL, NOT_VERIFY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile을 추가한다 - 테스트 및 등록성공에 필요한 최소한의 정보만 등록한다.
   */
  struct Dot2SecProfile profile;
  memset(&profile, 0, sizeof(profile));
  profile.psid = 135;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.rx.verify_data = false; // 수신데이터 검증을 하지 않도록 한다.
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * [TEST] SPDU 내 생성시각이 만기시각보다 미래인 경우에도 "성공"이 반환되는 것을 확인한다.
   * 서명이 유효하지 않은 샘플 데이터 이지만 verify_data=false이면 서명 검증도 수행하지 않으므로 성공한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_spdu_consistency_check_gentime_is_future_than_exptime;
    size_t spdu_size = g_sample_spdu_consistency_check_gentime_is_future_than_exptime_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
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
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}
