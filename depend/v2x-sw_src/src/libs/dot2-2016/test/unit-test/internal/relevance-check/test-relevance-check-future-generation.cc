/** 
  * @file 
  * @brief SPDU의 Future generation 관련 Relevance check 기능에 대한 단위테스트를 구현한 파일
  * @date 2021-09-11
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "certificate/cert-info/dot2-cert-info.h"
#include "sec-profile/dot2-sec-profile.h"
#include "spdu/dot2-spdu.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-relevance-check-sample-data.h"


/**
 * @brief SPDU의 Future generation 관련 Relevance check 기능(SPDU의 생성시각이 너무 미래인지 확인)이 정상적으로 동작하는 것을 확인한다.
 *
 */
TEST(FUTURE_GENERATION_RELEVANCE_CHECK, NORMAL)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry sec_profile_entry;
  struct Dot2SCCCertInfoEntry pca_entry, ica_entry, rca_entry;
  struct Dot2EECertCacheEntry signer_entry;
  struct Dot2SPDUProcessWorkData work_data;
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  work_data.parsed = parsed;
  Dot2Test_SetCertChain_ForRelevanceCheck(&signer_entry, &pca_entry, &ica_entry, &rca_entry);

  /*
   * [TEST1] Security profile이 Future generation check를 수행하지 않도록 설정되어 있는 경우, 생성시각이 매우 미래여도 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  parsed->spdu.signed_data.gen_time = SPDU_RELEVANCE_CHECK_RX_TIME + SPDU_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD + 1ULL; // 생성시각을 매우 미래로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST2] SPDU 내에 생성시각이 존재하지 않는 경우, 무조건 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_time_in_future = true; // Future generation 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time_present = false; // SPDU 내 생성시각이 존재하지 않도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST3] SPDU의 생성시각이 {수신시각 + 유효범위}보다 크면(너무 미래이면), "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_time_in_future = true; // Future generation 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time = SPDU_RELEVANCE_CHECK_RX_TIME + SPDU_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD + 1ULL; // 생성시각을 매우 미래로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_Future);

  /*
   * [TEST4] SPDU의 생성시각이 {수신시각 + 유효범위}와 같으면(허용될만한 미래이면), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_time_in_future = true; // Future generation 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time = SPDU_RELEVANCE_CHECK_RX_TIME + SPDU_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD; // 생성시각을 유효범위에 딱 맞게 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST4] SPDU의 생성시각이 {수신시각 + 유효범위}보다 작으면(허용될만한 미래이면), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_time_in_future = true; // Future generation 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time = SPDU_RELEVANCE_CHECK_RX_TIME + SPDU_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD - 1ULL; // 생성시각을 유효범위 내로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
