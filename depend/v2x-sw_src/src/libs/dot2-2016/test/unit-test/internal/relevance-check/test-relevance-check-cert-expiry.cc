/** 
  * @file 
  * @brief SPDU의 Certificate expiry 관련 Relevance check 기능에 대한 단위테스트를 구현한 파일
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
 * @brief SPDU의 Certificate expiry 관련 Relevance check 기능(인증서가 만기되었는지 확인)이 정상적으로 동작하는 것을 확인한다.
 *
 */
TEST(CERT_EXPIRY_RELEVANCE_CHECK, NORMAL)
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
   * [TEST1] Security profile이 Cert expiry check를 수행하지 않도록 설정되어 있는 경우, 인증서가 만기되었어도 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  work_data.params.rx_time = SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END + 1ULL; // SPDU 수신시각을 PCA 인증서 만기시각보다 미래로 설정한다.
  parsed->spdu.signed_data.gen_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 생성시각을 제거한다.
  parsed->spdu.signed_data.expiry_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 만기시각을 제거한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST2] SPDU 수신시각이 PCA 만기시각보다 과거이면(PCA/ICA/RCA 인증서 만기 전), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.cert_expiry = true; // Cert expiry 체크하도록 설정한다.
  work_data.params.rx_time = SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END - 1ULL; // SPDU 수신시각을 PCA 인증서 만기시각보다 과거로 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST3] SPDU 수신시각이 PCA 만기시각과 동일하면(PCA/ICA/RCA 인증서 만기 전), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.cert_expiry = true; // Cert expiry 체크하도록 설정한다.
  work_data.params.rx_time = SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END; // SPDU 수신시각을 PCA 인증서 만기시각으로 설정한다.
  parsed->spdu.signed_data.gen_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 생성시각을 제거한다.
  parsed->spdu.signed_data.expiry_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 만기시각을 제거한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);

  /*
   * [TEST4] SPDU 수신시각이 PCA 만기시각보다 미래이면(PCA 인증서 만기, ICA/RCA 인증서 만기 전), "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.cert_expiry = true; // Cert expiry 체크하도록 설정한다.
  work_data.params.rx_time = SPDU_RELEVANCE_CHECK_PCA_CERT_VALID_END + 1ULL; // SPDU 수신시각을 PCA 인증서 만기시각보다 미래로 설정한다.
  parsed->spdu.signed_data.gen_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 생성시각을 제거한다.
  parsed->spdu.signed_data.expiry_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 만기시각을 제거한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_CertExpiry);

  /*
   * [TEST5] SPDU 수신시각이 ICA 만기시각보다 미래이면(PCA/ICA 인증서 만기, RCA 인증서 만기 전), "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.cert_expiry = true; // Cert expiry 체크하도록 설정한다.
  work_data.params.rx_time = SPDU_RELEVANCE_CHECK_ICA_CERT_VALID_END + 1ULL; // SPDU 수신시각을 ICA 인증서 만기시각보다 미래로 설정한다.
  parsed->spdu.signed_data.gen_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 생성시각을 제거한다.
  parsed->spdu.signed_data.expiry_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 만기시각을 제거한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_CertExpiry);

  /*
   * [TEST6] SPDU 수신시각이 RCA 만기시각보다 미래이면(PCA/ICA/RCA 인증서 만기), "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.cert_expiry = true; // Cert expiry 체크하도록 설정한다.
  work_data.params.rx_time = SPDU_RELEVANCE_CHECK_RCA_CERT_VALID_END + 1ULL; // SPDU 수신시각을 RCA 인증서 만기시각보다 미래로 설정한다.
  parsed->spdu.signed_data.gen_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 생성시각을 제거한다.
  parsed->spdu.signed_data.expiry_time_present = false; // 먼저 수행되는 Freshness check에서 실패하는 것을 방지하기 위해 SPDU에서 만기시각을 제거한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_CertExpiry);

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
