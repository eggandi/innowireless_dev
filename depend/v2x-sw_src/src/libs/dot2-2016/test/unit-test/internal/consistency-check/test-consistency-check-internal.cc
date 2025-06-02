/** 
  * @file 
  * @brief SPDU 내부 consistency check 기능에 대한 단위테스트를 구현한 파일
  * @date 2021-09-06 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cert-info/dot2-cert-info.h"
#include "spdu/dot2-spdu.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-consistency-check-sample-data.h"


/**
 * @brief SPDU 내부 Consistency check 기능이 정상적으로 동작하는 것을 확인한다.
 */
TEST(INTERNAL_CONSISTENCY_CHECK, ALL)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfile sec_profile;
  struct Dot2EECertCacheEntry signer_entry;
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  Dot2Test_SetSecurityProfile(&sec_profile);
  Dot2Test_SetSampleCircularSignerCertEntry(&signer_entry);

  /*
   * [TEST1] SPDU 내에 생성시각과 만기시각이 모두 없는 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false;
  parsed->spdu.signed_data.expiry_time_present = false;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST2] SPDU 내에 생성시각만 존재하고 만기시각은 존재하지 않는 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.expiry_time_present = false;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST3] SPDU 내에 생성시각은 존재하지 않고 만기시각만 존재하는 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.gen_time_present = false;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST4] SPDU 내에 생성시각과 만기시각이 모두 존재하는 존재하는 경우,
   *  만기시각이 생성시각과 같으면 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.expiry_time = parsed->spdu.signed_data.gen_time;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST5] SPDU 내에 생성시각과 만기시각이 모두 존재하는 존재하는 경우,
   *  만기시각이 생성시각보다 크면(이후) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.expiry_time = parsed->spdu.signed_data.gen_time + 1ULL;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), kDot2Result_Success);

  /*
   * [TEST6] SPDU 내에 생성시각과 만기시각이 모두 존재하는 존재하는 경우,
   *  만기시각이 생성시각보다 작으면(이전) "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetPacketParseData(parsed);
  parsed->spdu.signed_data.expiry_time = parsed->spdu.signed_data.gen_time - 1ULL;
  ASSERT_EQ(dot2_CheckSPDUConsistency(parsed, &sec_profile, &signer_entry), -kDot2Result_SPDUConsistency_ExpTimeBeforeGenTimeInSPDU);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
