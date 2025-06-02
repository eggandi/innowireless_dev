/** 
  * @file 
  * @brief SPDU의 Location 관련 Relevance check 기능에 대한 단위테스트를 구현한 파일
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
 * @brief SPDU의 Location 관련 Relevance check 기능(SPDU의 생성지점이 너무 먼곳인지 확인)이 정상적으로 동작하는 것을 확인한다.
 *
 */
TEST(OCATION_RELEVANCE_CHECK, NORMAL)
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
   * [TEST1] Security profile이 Location check를 수행하지 않도록 설정되어 있는 경우, 생성지점이 매우 멀어도 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  parsed->spdu.signed_data.gen_location.lat = SPDU_RELEVANCE_CHECK_RX_LAT + SPDU_RELEVANCE_CHECK_11000M_OFFSET_LAT; // 생성위도를 매우 먼곳으로 설정한다.
  parsed->spdu.signed_data.gen_location.lon = SPDU_RELEVANCE_CHECK_RX_LON + SPDU_RELEVANCE_CHECK_11000M_OFFSET_LON; // 생성경도를 매우 먼곳으로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST2] SPDU 내에 생성좌표가 존재하지 않는 경우, 무조건 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_location_distance = true; // Location 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_location_present = false; // SPDU 내 생성좌표가 존재하지 않도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST3] SPDU의 생성좌표가 {수신지점 + 유효범위} 밖에 있으면(너무 멀면), "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_location_distance = true; // Location 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_location.lat = SPDU_RELEVANCE_CHECK_RX_LAT + SPDU_RELEVANCE_CHECK_11000M_OFFSET_LAT; // 생성위도를 매우 먼곳으로 설정한다.
  parsed->spdu.signed_data.gen_location.lon = SPDU_RELEVANCE_CHECK_RX_LON + SPDU_RELEVANCE_CHECK_11000M_OFFSET_LON; // 생성경도를 매우 먼곳으로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_Location);

  /*
   * [TEST4] SPDU의 생성좌표가 {수신시각 + 유효범위} 내에 있으면(허용될만한 거리이면), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.gen_location_distance = true; // Location 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_location.lat = SPDU_RELEVANCE_CHECK_RX_LAT + SPDU_RELEVANCE_CHECK_9000M_OFFSET_LAT; // 생성위도를 허용될만한 먼곳으로 설정한다.
  parsed->spdu.signed_data.gen_location.lon = SPDU_RELEVANCE_CHECK_RX_LON + SPDU_RELEVANCE_CHECK_9000M_OFFSET_LON; // 생성경도를 허용될만한 먼곳으로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
