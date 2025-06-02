/** 
  * @file 
  * @brief SignedData 유형의 SPDU에 대한 Dot2_ProcessSPDU() API 동작 단위테스트 구현 파일
  * @date 2021-06-22 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 최소 헤더를 갖는 SignedData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, SUCCESS_WHEN_MIN_HEADER_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 최소 헤더를 갖는 SignedData 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_min_header_signed_data; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_min_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
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
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 최대 헤더를 갖는 SignedData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, SUCCESS_WHEN_MAX_HEADER_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 최대 헤더를 갖는 SignedData 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data; // 최대 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 Uncompressed 서명을 포함한 SignedData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, SUCCESS_WHEN_UNCOMPRESSED_SIGNED_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 Uncompressed 서명을 포함한 SignedData 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_uncompressed_signed_data; // Uncompressed 서명이 포함된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_uncompressed_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 499569185000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 499569245000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 X-only 서명을 포함한 SignedData를 전달하면 정상적으로 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, SUCCESS_WHEN_X_ONLY_SIGNED_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 X-only 서명을 포함한 SignedData 전달 시 정상 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_x_only_signed_data; // X-only 서명이 포함된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_x_only_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 499569545000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 499569605000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 Digest로 서명된 SignedData를 전달하면 정상적으로 처리되는 것을 확인한다.
 *
 * (1) 처음 digest로 서명된 SPDU를 수신하면, 처리에 실패해야 한다. (서명검증할 인증서정보가 없으므로)
 * (2) 이후 certificate로 서명된 SPDU를 수신하면 처리에 성공해야 한다.
 * (3) 이후 digest로 서명된 SPDU를 수신하면 처리에 성공해야 한다. ((2)번 단계에서 서명검증할 인증서정보가 확보되었으므로)
 */
TEST(Dot2_ProcessSPDU_SignedData, SUCCESS_WHEN_DIGEST_SIGNED_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 Digest로 서명된 SignedData 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   * 아직 서명자 인증서 정보가 저장되어 있지 않으므로 처리할 수가 없다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_digest_signed_data; // Digest로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_digest_signed_data_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 실패 결과 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDU_NoSignerIdCertInTable);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * spdu 인자로 인증서로 서명된 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 이를 통해 서명자 인증서 정보가 저장된다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data; // 인증서로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[1].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[1].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * spdu 인자로 Digest로 서명된 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 앞에서 서명자 인증서 정보가 저장되었으므로 이제 처리 가능하다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_digest_signed_data; // Digest로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_digest_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 3U);
    ASSERT_EQ(g_callbacks.entry[2].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Digest); // Digest로 서명
    ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time, 499569981000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time, 499570041000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[2].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장된 상태를 유지하는 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 페이로드가 변조된 SignedData를 전달하면 정상적으로 서명 검증 실패 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_TAMPERED_PAYLOAD_1)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 페이로드가 변조된 SignedData를 전달하면 서명 검증에 실패하는 것을 확인한다.
   */
  {
    // 페이로드 변조 (페이로드의 마지막 바이트의 값을 1 증가)
    uint8_t payload_tampered_spdu[kDot2SPDUSize_Max];
    size_t payload_tampered_spdu_size = g_sample_max_header_signed_data_size;
    memcpy(payload_tampered_spdu, g_sample_max_header_signed_data, g_sample_max_header_signed_data_size);
    payload_tampered_spdu[45]++;

    // API 호출 성공 확인 (서명검증 실패 결과는 콜백함수를 통해 전달됨)
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = payload_tampered_spdu; // 페이로드가 변조된 SPDU
    size_t spdu_size = payload_tampered_spdu_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과 확인 (서명검증실패)
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SignatureVerificationFailed);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 페이로드가 변조된 SignedData를 전달하면 정상적으로 서명 검증 실패 처리되는 것을 확인한다.
 * FAIL_WHEN_TAMPERED_PAYLOAD_1 테스트와 다른 점은, 정상적인 SignedData 로 서명 검증을 먼저 수행한 후 변조된 SignedData를 처리한다는 것이다.
 * 이를 수행하는 이유는 첫 SignedData일 경우 공개키 재구성을 거쳐서 서명검증을 수행하지만,
 * 두번째 SignedData일 경우 공개키 재구성을 거치지 않고 서명검증을 수행하여 실행 루틴이 다소 다르기 때문이다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_TAMPERED_PAYLOAD_2)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 정상 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 서명자(인증서)의 공개키가 재구성되어 저장된다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data; // 정상 SPDU
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * spdu 인자로 페이로드가 변조된 SPDU를 전달하면 서명 검증에 실패하는 것을 확인한다.
   * 서명자(인증서)의 공개키는 이미 저장되어 있으므로, 바로 서명검증을 수행하는 루틴이 실행된다.
   */
  {
    // 페이로드 변조 (페이로드의 마지막 바이트의 값을 1 증가)
    uint8_t payload_tampered_spdu[kDot2SPDUSize_Max];
    size_t payload_tampered_spdu_size = g_sample_max_header_signed_data_size;
    memcpy(payload_tampered_spdu, g_sample_max_header_signed_data, g_sample_max_header_signed_data_size);
    payload_tampered_spdu[45]++;

    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = payload_tampered_spdu; // 페이로드가 변조된 SPDU
    size_t spdu_size = payload_tampered_spdu_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 실패 결과를 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_SignatureVerificationFailed);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장된 상태를 유지하는 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 서명이 변조된 SignedData를 전달하면 정상적으로 서명 검증 실패 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_TAMPERED_SIGN_1)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 서명이 변조된 SignedData를 전달하면 서명 검증에 실패하는 것을 확인한다.
   */
  {
    // 서명 변조 (서명 s의 마지막 바이트의 값을 1 증가)
    uint8_t sign_tampered_spdu[kDot2SPDUSize_Max];
    size_t sign_tampered_spdu_size = g_sample_max_header_signed_data_size;
    memcpy(sign_tampered_spdu, g_sample_max_header_signed_data, g_sample_max_header_signed_data_size);
    sign_tampered_spdu[g_sample_max_header_signed_data_size-1]++;

    // API 호출 성공 확인 (서명검증 실패 결과는 콜백함수를 통해 전달됨)
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = sign_tampered_spdu; // 서명이 변조된 SPDU
    size_t spdu_size = sign_tampered_spdu_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과 확인 (서명검증실패)
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SignatureVerificationFailed);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 서명이 변조된 SignedData를 전달하면 정상적으로 서명 검증 실패 처리되는 것을 확인한다.
 * FAIL_WHEN_TAMPERED_SIGN_1 테스트와 다른 점은, 정상적인 SignedData 로 서명 검증을 먼저 수행한 후 변조된 SignedData를 처리한다는 것이다.
 * 이를 수행하는 이유는 첫 SignedData일 경우 공개키 재구성을 거쳐서 서명검증을 수행하지만,
 * 두번째 SignedData일 경우 공개키 재구성을 거치지 않고 서명검증을 수행하여 실행 루틴이 다소 다르기 때문이다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_TAMPERED_SIGN_2)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 정상 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 서명자(인증서)의 공개키가 재구성되어 저장된다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data; // 정상 SPDU
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * spdu 인자로 서명이 변조된 SPDU를 전달하면 서명 검증에 실패하는 것을 확인한다.
   * 서명자(인증서)의 공개키는 이미 저장되어 있으므로, 바로 서명검증을 수행하는 루틴이 실행된다.
   */
  {
    // 서명 변조 (서명 s의 마지막 바이트의 값을 1 증가)
    uint8_t sign_tampered_spdu[kDot2SPDUSize_Max];
    size_t sign_tampered_spdu_size = g_sample_max_header_signed_data_size;
    memcpy(sign_tampered_spdu, g_sample_max_header_signed_data, g_sample_max_header_signed_data_size);
    sign_tampered_spdu[g_sample_max_header_signed_data_size-1]++;

    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = sign_tampered_spdu; // 서명이 변조된 SPDU
    size_t spdu_size = sign_tampered_spdu_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과 확인 (서명검증실패)
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_SignatureVerificationFailed);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장된 상태를 유지하는 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 비정상 SignedData를 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_ABNORMAL_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 비정상 SignedData 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data + 1; // 비정상 데이터로 변경
    size_t spdu_size = g_sample_max_header_signed_data_size - 1; // 비정상 데이터로 변경
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과 확인 (디코딩 실패)
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDU_DecodeSPDU);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 spdu 인자로 NULL로 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_NULL_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 NULL로 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = nullptr; // Null SPDU
    size_t spdu_size = g_sample_max_header_signed_data_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), -kDot2Result_SPDU_NullParameters);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
    V2X_FreePacketParseData(parsed); // 콜백함수가 호출되지 않았으므로 여기서 해제한다.
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 parsed 인자로 NULL로 전달하면 정상적으로 에러 처리되는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, FAIL_WHEN_NULL_PARSED)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
   * CA 인증서 등록
   */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * parsed 인자로 NULL로 전달하면 정상적으로 에러 처리하는 것을 확인한다.
   */
  {
    // API 호출 실패 확인
    uint8_t *spdu = g_sample_max_header_signed_data;
    size_t spdu_size = g_sample_max_header_signed_data_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, nullptr), -kDot2Result_SPDU_NullParameters);

    // 콜백함수가 호출되지 않은 것을 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 0U);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief 대량 메시지 수신 처리 테스트
 */
TEST(Dot2_ProcessSPDU_SignedData, SUCCESS_WHEN_MANY_SPDU)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 Digest로 서명된 SignedData 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   * 아직 서명자 인증서 정보가 저장되어 있지 않으므로 처리할 수가 없다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_digest_signed_data; // Digest로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_digest_signed_data_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success); // 에러: 서명자 인증서 찾지 못함

    // 콜백함수로 전달된 결과 확인 (서명자인증서 찾지 못함)
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SPDU_NoSignerIdCertInTable);
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장되지 않은 것을 확인한다.
   */
  Dot2Test_CheckNoRSE0AppCert();
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);

  /*
   * spdu 인자로 인증서로 서명된 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 이를 통해 서명자 인증서 정보가 저장된다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data; // 인증서로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[1].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[1].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * spdu 인자로 Digest로 서명된 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 앞에서 서명자 인증서 정보가 저장되었으므로 이제 처리 가능하다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_digest_signed_data; // Digest로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_digest_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 3U);
    ASSERT_EQ(g_callbacks.entry[2].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Digest); // Digest로 서명
    ASSERT_FALSE(g_callbacks.entry[2].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_time, 499569981000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.expiry_time, 499570041000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[2].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[2].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[2].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장된 상태를 유지하는 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 다음 테스트를 위해 SPDU 처리 결과 리스트를 비운다.
   */
  Dot2Test_FlushProcessSPDUCallbackList();


// 테스트 SPDU 개수 (MAX_ENTRY_NUM 이하의 값을 사용해야 한다)
#undef TEST_SPDU_NUM
#define TEST_SPDU_NUM (100000U)

// 메시지 처리 작업큐 오버플로우를 방지하기 위한 각 메시지 사이에 삽입되는 지연 (usec)
#undef INTER_SPDU_GAP
#define INTER_SPDU_GAP (100U)

/*
 * 대량의 메시지에 대한 수신 처리를 요청한다.
 * 대량의 인증서로 서명된 SignedData, Digest로 서명된 SignedData를 처리한다.
 * 플랫폼의 서명검증 성능에 따라 TEST_SPDU_NUM의 개수를 조절하여 테스트한다.
 * 현재 TEST_SPDU_NUM = 100000U, INTER_MSG_GAP = 100U 일 때 20초 정도 소요됨.
 * API 호출 결과로 -kDot2Result_SPDUProcessWorkRequestQueueFull(작업요청큐 오버플로우)가 리턴되면, INTER_SPDU_GAP 값을 늘려 준다.
 */
  struct V2XPacketParseData *parsed;
  for (unsigned int i = 0; i < TEST_SPDU_NUM; i++) {
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    if (i%2 == 0) {
      ASSERT_EQ(Dot2_ProcessSPDU(g_sample_max_header_signed_data, g_sample_max_header_signed_data_size, &params, parsed), kDot2Result_Success);
    } else {
      ASSERT_EQ(Dot2_ProcessSPDU(g_sample_digest_signed_data, g_sample_digest_signed_data_size, &params, parsed), kDot2Result_Success);
    }
    usleep(INTER_SPDU_GAP); // 메시지 처리 작업큐 오버플로우를 방지하기 위한 지연 삽입
  }

  /*
   * 모든 메시지에 대한 처리가 완료될 때까지 기다린다.
   */
  sleep(5);

  /*
   * 처리 결과 개수를 확인한다.
   */
  ASSERT_EQ(g_callbacks.cnt, TEST_SPDU_NUM);

  /*
   * 각 메시지 별 처리결과가 정확한지 확인한다.
   */
  for (unsigned int i = 0; i < TEST_SPDU_NUM; i++) {
    if (i%2 == 0) {
      ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
      ASSERT_FALSE(g_callbacks.entry[i].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.psid, 135U); // PSID 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr); // 페이로드 비교
      ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
      ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
    } else {
      ASSERT_EQ(g_callbacks.entry[i].result, kDot2Result_Success);
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Digest); // Digest로 서명
      ASSERT_FALSE(g_callbacks.entry[i].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.psid, 135U); // PSID 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_time, 499569981000000ULL); // 생성시각 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.expiry_time, 499570041000000ULL); // 만기시각 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
      ASSERT_EQ(g_callbacks.entry[i].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
      ASSERT_TRUE(g_callbacks.entry[i].parsed->ssdu != nullptr); // 페이로드 비교
      ASSERT_EQ(g_callbacks.entry[i].parsed->ssdu_size, g_sample_signed_data_payload_size); // 페이로드 비교
      ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[i].parsed->ssdu, g_sample_signed_data_payload, g_sample_signed_data_payload_size)); // 페이로드 비교
    }
  }

  /*
   * 수신 메시지에 포함된 App 인증서가 중복등록되거나 정보가 변하지 않았음을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Dot2_ProcessSPDU() 호출 시 오버플로우가 발생해도 정상 동작하는 것을 확인한다.
 */
TEST(Dot2_ProcessSPDU_SignedData, NOT_FAULT_WHEN_OVERFLOW)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  /*
   * spdu 인자로 인증서로 서명된 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 이를 통해 서명자 인증서 정보가 저장된다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_max_header_signed_data; // 인증서로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_max_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time, 499567875000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time, 499567935000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 정상 저장된 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * spdu 인자로 Digest로 서명된 SignedData 전달 시 정상적으로 처리하는 것을 확인한다.
   * 앞에서 서명자 인증서 정보가 저장되었으므로 이제 처리 가능하다.
   */
  {
    // API 호출 성공 확인
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_digest_signed_data; // Digest로 서명된 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_digest_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Digest); // Digest로 서명
    ASSERT_FALSE(g_callbacks.entry[1].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.psid, 135U); // PSID 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time_present); // 생성시각 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_time, 499569981000000ULL); // 생성시각 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time_present); // 만기시각 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.expiry_time, 499570041000000ULL); // 만기시각 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location_present); // 생성좌표 포함
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.lat, 374857139); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.lon, 1270392170); // 생성좌표 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->spdu.signed_data.gen_location.elev, 0U); // 생성좌표 비교
    ASSERT_TRUE(g_callbacks.entry[1].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[1].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[1].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * SignedData에 포함된 서명자(인증서)가 저장된 상태를 유지하는 것을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

// 테스트 SPDU 개수 (MAX_ENTRY_NUM 이하의 값을 사용해야 한다)
#undef TEST_SPDU_NUM
#define TEST_SPDU_NUM (100000U)

  /*
   * 대량의 메시지에 대한 수신 처리를 요청한다.
   * 대량의 인증서로 서명된 SignedData, Digest로 서명된 SignedData를 처리한다.
   * API 호출 결과가 성공 또는 Queue full 중 하나인 것을 확인한다.
   */
  struct V2XPacketParseData *parsed;
  int ret;
  for (unsigned int i = 0; i < TEST_SPDU_NUM; i++) {
    parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
    if (i%2 == 0) {
      ret = Dot2_ProcessSPDU(g_sample_max_header_signed_data, g_sample_max_header_signed_data_size, &params, parsed);
      ASSERT_TRUE((ret == kDot2Result_Success) || (ret == -kDot2Result_SPDUProcessWorkRequestQueueFull));
    } else {
      ret = Dot2_ProcessSPDU(g_sample_digest_signed_data, g_sample_digest_signed_data_size, &params, parsed);
      ASSERT_TRUE((ret == kDot2Result_Success) || (ret == -kDot2Result_SPDUProcessWorkRequestQueueFull));
    }
  }

  /*
   * 모든 메시지에 대한 처리가 완료될 때까지 기다린다.
   */
  sleep(1);

  /*
   * 수신 메시지에 포함된 App 인증서가 중복등록되거나 정보가 변하지 않았음을 확인한다.
   */
  Dot2Test_CheckRegisteredRSE0AppCert(true);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);

  /*
   * 종료
   */
  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}

