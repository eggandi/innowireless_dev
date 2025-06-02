/** 
  * @file 
  * @brief SPDU와 서명자인증서 간 만기시각 관련 Consistency check 기능에 대한 단위테스트를 구현한 파일
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
 * @brief SPDU와 서명자인증서 간 만기시각 관련 Consistency check 기능이 정상적으로 동작하는 것을 확인한다.
 */
TEST(EXPIRY_TIME_CONSISTENCY_CHECK, NORMAL)
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
   * [TEST1] SPDU 내에 만기시각이 존재하지 않는 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU에서 생성좌표를 제외하여 생성좌표 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time_present = false;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST2] SPDU 내에 만기시각이 존재하고, 만기시각이 인증서 유효기간 시작시점보다 이전인 경우 "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU에서 생성좌표를 제외하여 생성좌표 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time = signer_entry.contents.common.valid_start - 1ULL;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), -kDot2Result_SPDUConsistency_ExpTimeIsNotInSignerValidPeriod);

  /*
   * [TEST3] SPDU 내에 만기시각이 존재하고, 만기시각이 인증서 유효기간 시작시점과 동일한 경우 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU에서 생성좌표를 제외하여 생성좌표 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time = signer_entry.contents.common.valid_start;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST4] SPDU 내에 만기시각이 존재하고, 만기시각이 인증서 유효기간 시작시점과 종료시점 사이에 있을 경우 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU에서 생성좌표를 제외하여 생성좌표 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time = signer_entry.contents.common.valid_start + 1ULL;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST5] SPDU 내에 만기시각이 존재하고, 만기시각이 인증서 유효기간 종료시점과 동일한 경우 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU에서 생성좌표를 제외하여 생성좌표 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time = signer_entry.contents.common.valid_end;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST6] SPDU 내에 만기시각이 존재하고, 만기시각이 인증서 유효기간 종료시점보다 이후인 경우 "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false; // SPDU에서 생성시각을 제외하여 생성시각 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU에서 생성좌표를 제외하여 생성좌표 관련 consistency check가 수행되지 않도록 한다.
  parsed->spdu.signed_data.expiry_time = signer_entry.contents.common.valid_end + 1ULL;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), -kDot2Result_SPDUConsistency_ExpTimeIsNotInSignerValidPeriod);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
