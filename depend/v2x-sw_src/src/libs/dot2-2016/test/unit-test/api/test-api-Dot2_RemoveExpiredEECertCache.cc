/**
  * @file
  * @brief Dot2_RemoveExpiredEECertCache() API 동작 단위테스트 구현 파일
  * @date 2023-02-23
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_RemoveExpiredEECertCache() API 호출시 인증서캐시만기에 대한 동작을 확인한다.
 */
TEST(API_Dot2_RemoveExpiredEECertCache, CACHE_EXPIRY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  struct Dot2EECertCacheEntry *ee_cert_cache_entry = nullptr;

  /*
  * SCC인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_rca_cert, g_sample_rca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_ica_cert, g_sample_ica_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_eca_cert, g_sample_eca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_pca_cert, g_sample_pca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_ra_cert, g_sample_ra_cert_size), 0);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5U);

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  SAVE_TEST_START_TIME;

  /*
   * 테스트용 SPDU 내 포함된 g_sample_rse_0_cert의 인증서 유효기간 내로 시스템시간을 변경한다.
   */
  Dot2Time64 cert_start = g_sample_rse_0_valid_start; // 2019-10-30 13:03:03 UTC
  Dot2Time64 cert_exp = g_sample_rse_0_valid_end; // 2019-12-04 23:03:03 UTC
  system("date -s '2019-10-30 13:03:05'");

  /*
   * SPDU를 하나 수신하여 EE인증서캐시가 생긴 것을 확인한다.
   * 테스트용 SPDU(g_sample_min_header_signed_data)의 SignerIdentifier에는 g_sample_rse_0_cert가 들어 있다.
   */
  // SPDU 수신
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  uint8_t *spdu = g_sample_min_header_signed_data; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
  size_t spdu_size = g_sample_min_header_signed_data_size;
  struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
  ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);
  WAIT_MSG_PROCESS_CALLBACK;
  // EE인증서캐시 확인
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);
  ee_cert_cache_entry = TAILQ_FIRST(&(g_dot2_mib.ee_cert_cache_table.list[0x49].head));
  ASSERT_TRUE(ee_cert_cache_entry != nullptr);
  ASSERT_EQ(ee_cert_cache_entry->contents.common.valid_end, cert_exp);
  Dot2Time64 cache_exp = ee_cert_cache_entry->expiry;

  Dot2Time64 exp;

  /*
   * API 호출시 만기시각을 EE 인증서캐시 만기 이전으로 전달하면 인증서캐시가 삭제되지 않는 것을 확인한다.
   */
  exp = cache_exp - 1ULL;
  Dot2_RemoveExpiredEECertCache(exp);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);

  /*
   * API 호출시 만기시각을 EE 인증서캐시 만기 이후로 전달하면 인증서캐시가 삭제되는 것을 확인한다.
   */
  exp = cache_exp + 1ULL;
  Dot2_RemoveExpiredEECertCache(exp);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 0U);

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}


/**
 * @brief Dot2_RemoveExpiredEECertCache() API 호출시 인증서 유효기간만기에 대한 동작을 확인한다.
 */
TEST(API_Dot2_RemoveExpiredEECertCache, CERT_EXPIRY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  struct Dot2EECertCacheEntry *ee_cert_cache_entry = nullptr;

  /*
  * SCC인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_rca_cert, g_sample_rca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_ica_cert, g_sample_ica_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_eca_cert, g_sample_eca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_pca_cert, g_sample_pca_cert_size), 0);
  ASSERT_EQ(Dot2_AddSCCCert(g_sample_ra_cert, g_sample_ra_cert_size), 0);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5U);

  /*
   * Security profile 등록
   */
  struct Dot2SecProfile sec_profile{};
  memset(&sec_profile, 0, sizeof(sec_profile));
  sec_profile.psid = 135;
  sec_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  sec_profile.rx.verify_data = true;
  ASSERT_EQ(Dot2_AddSecProfile(&sec_profile), kDot2Result_Success);

  Dot2Time64 cert_exp = g_sample_rse_0_valid_end; // 2019-12-04 23:03:03 UTC

  /*
   * SPDU를 하나 수신하여 EE인증서캐시가 생긴 것을 확인한다.
   * 테스트용 SPDU(g_sample_min_header_signed_data)의 SignerIdentifier에는 g_sample_rse_0_cert가 들어 있다.
   */
  // SPDU 수신
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  uint8_t *spdu = g_sample_min_header_signed_data; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
  size_t spdu_size = g_sample_min_header_signed_data_size;
  struct Dot2SPDUProcessParams params = {0, 135, {374063230L, 1271023340L}};
  ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);
  WAIT_MSG_PROCESS_CALLBACK;
  // EE인증서캐시 확인
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);
  ee_cert_cache_entry = TAILQ_FIRST(&(g_dot2_mib.ee_cert_cache_table.list[0x49].head));
  ASSERT_TRUE(ee_cert_cache_entry != nullptr);
  ASSERT_EQ(ee_cert_cache_entry->contents.common.valid_end, cert_exp);

  Dot2Time64 exp;

  /*
   * API 호출시 만기시각을 EE 인증서 만기 이전으로 전달하면 인증서캐시가 삭제되지 않는 것을 확인한다.
   */
  exp = cert_exp - 1ULL;
  Dot2_RemoveExpiredEECertCache(exp);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);

  /*
   * API 호출시 만기시각을 EE 인증서 만기시각으로 전달하면 인증서캐시가 삭제되지 않는 것을 확인한다.
   */
  exp = cert_exp;
  Dot2_RemoveExpiredEECertCache(exp);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);

  /*
   * API 호출시 만기시각을 EE 인증서 만기시각 이후로 전달하면 인증서캐시가 삭제되는 것을 확인한다.
   */
  exp = cert_exp + 1;
  Dot2_RemoveExpiredEECertCache(exp);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 0U);

  SAVE_TEST_START_TIME;

  /*
   * 테스트용 SPDU 내 포함된 g_sample_rse_0_cert의 인증서 유효기간 내로 시스템시간을 변경한다.
   * 인증서 만기시각(2019-12-04 23:03:03 UTC)이 인증서캐시 만기시각(테스트시각 + DOT2_EE_CERT_CACHE_VALID_USEC)보다 먼저이도록 시간을 설정한다.
   */
  system("date -s '2019-12-04 23:02:50'");

  /*
   * SPDU를 하나 수신하여 EE인증서캐시가 생긴 것을 확인한다.
   * 테스트용 SPDU(g_sample_min_header_signed_data)의 SignerIdentifier에는 g_sample_rse_0_cert가 들어 있다.
   */
  // SPDU 수신
  ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);
  WAIT_MSG_PROCESS_CALLBACK;
  // EE인증서캐시 확인
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);
  ee_cert_cache_entry = TAILQ_FIRST(&(g_dot2_mib.ee_cert_cache_table.list[0x49].head));
  ASSERT_TRUE(ee_cert_cache_entry != nullptr);
  ASSERT_EQ(ee_cert_cache_entry->contents.common.valid_end, cert_exp);
  Dot2Time64 cache_exp = ee_cert_cache_entry->expiry;
  ASSERT_TRUE(cert_exp < cache_exp); /// 인증서 만기시각이 인증서캐시 만기시각보다 작은것을 확인한다.

  /*
   * 현재시각이 인증서 만기시각(2019-12-04 23:03:03 UTC) 이전이므로, API 호출시 만기시각을 0으로 전달하면 캐시가 삭제되지 않는 것을 확인한다.
   */
  Dot2_RemoveExpiredEECertCache(0);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 1U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 1U);

  /*
   * 현재시각이 인증서 만기시각(2019-12-04 23:03:03 UTC) 이후이면, API 호출시 만기시각을 0으로 전달하면 캐시가 삭제되는 것을 확인한다.
   */
  system("date -s '2019-12-04 23:03:05'");
  Dot2_RemoveExpiredEECertCache(0);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.entry_num, 0U);
  ASSERT_EQ(g_dot2_mib.ee_cert_cache_table.list[0x49].entry_num, 0U);

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}
