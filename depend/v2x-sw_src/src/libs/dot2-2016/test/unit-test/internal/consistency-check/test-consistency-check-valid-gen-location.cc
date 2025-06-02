/** 
  * @file 
  * @brief SPDU와 서명자인증서 간 생성좌표 관련 Consistency check 기능에 대한 단위테스트를 구현한 파일
  * @date 2021-09-06
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cert-info/dot2-cert-info.h"
#include "certificate/cert-info/dot2-ee-cert-cache.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-consistency-check-sample-data.h"


/**
 * @brief SPDU와 서명자인증서(원형 유효지역) 간 생성좌표 관련 Consistency check 기능이 정상적으로 동작하는 것을 확인한다.
 */
TEST(GEN_LOCATION_CONSISTENCY_CHECK, CIRCULAR_REGION)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfile sec_profile{};
  struct Dot2EECertCacheEntry signer_entry;
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  Dot2Test_SetSecurityProfile(&sec_profile);
  Dot2Test_SetSampleCircularSignerCertEntry(&signer_entry);

  /*
   * [TEST1] SPDU 내에 생성좌표가 존재하지 않는 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time_present = false; // SPDU에서 만기시각을 제외하여 만기시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST2] SPDU 내에 생성좌표가 존재하고, 생성좌표가 인증서 유효지역 내에 있는 경우 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time_present = false; // SPDU에서 만기시각을 제외하여 만기시각 관련 consistency check가 수행되지 않도록 한다.
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST3] SPDU 내에 생성좌표가 존재하고, 생성좌표가 인증서 유효지역 밖에 있는 경우 "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time_present = false; // SPDU에서 만기시각을 제외하여 만기시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location.lat = SPDU_LAT_TOO_FAR_FROM_CERT_VALID_REGION; // 인증서 유효지역 밖의 지점
  parsed->spdu.signed_data.gen_location.lon = SPDU_LON_TOO_FAR_FROM_CERT_VALID_REGION; // 인증서 유효지역 밖의 지점
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), -kDot2Result_SPDUConsistency_GenLocationIsNotInSignerValidRegion);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}


/**
 * @brief SPDU와 서명자인증서(Identified 유형 유효지역) 간 생성좌표 관련 Consistency check 기능이 정상적으로 동작하는 것을 확인한다.
 */
TEST(GEN_LOCATION_CONSISTENCY_CHECK, IDENTIFIED_REGION)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfile sec_profile{};
  struct Dot2EECertCacheEntry signer_entry;
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  Dot2Test_SetSecurityProfile(&sec_profile);
  Dot2Test_SetSampleCircularSignerCertEntry(&signer_entry);

  /*
   * [TEST1] 인증서 유효지역이 Identified 유형인 경우, SPDU 내 생성좌표 값과 무관하게 무조건 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time_present = false; // SPDU에서 만기시각을 제외하여 만기시각 관련 consistency check가 수행되지 않도록 한다.
  signer_entry.contents.common.valid_region.type = kDot2CertValidRegionType_Identified;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);
  parsed->spdu.signed_data.gen_location.lat = SPDU_LAT_TOO_FAR_FROM_CERT_VALID_REGION; // 원형/사각형 인증서 유효지역 밖의 지점
  parsed->spdu.signed_data.gen_location.lon = SPDU_LON_TOO_FAR_FROM_CERT_VALID_REGION; // 원형/사각형 인증서 유효지역 밖의 지점
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}


/**
 * @brief 서명자인증서 내 유효지역 유형이 유효하지 않을 경우,
 *        SPDU와 서명자인증서 간 생성좌표 관련 Consistency check 기능이 수행되지 않는 것을 확인한다.
 */
TEST(GEN_LOCATION_CONSISTENCY_CHECK, INVALID_REGION)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfile sec_profile{};
  struct Dot2EECertCacheEntry signer_entry;
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  Dot2Test_SetSecurityProfile(&sec_profile);
  Dot2Test_SetSampleCircularSignerCertEntry(&signer_entry);

  /*
   * [TEST1] 인증서 유효지역이 유효하지 않은 경우, SPDU 내 생성좌표값에 무관하게 "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time_present = false; // SPDU에서 만기시각을 제외하여 만기시각 관련 consistency check가 수행되지 않도록 한다.
  signer_entry.contents.common.valid_region.type = kDot2CertValidRegionType_None;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), -kDot2Result_SPDUConsistency_InvalidSignerRegionType);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
