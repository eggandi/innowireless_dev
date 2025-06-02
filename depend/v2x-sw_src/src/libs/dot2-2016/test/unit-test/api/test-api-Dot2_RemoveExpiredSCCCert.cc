/**
  * @file
  * @brief Dot2_RemoveExpiredSCCCert() API 동작 단위테스트 구현 파일
  * @date 2023-02-23
  * @author gyun
  */


// 시스템 헤더 파일
#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"



/**
 * @brief Dot2_RemoveExpiredSCCCert() API의 기본 동작을 확인한다.
 */
TEST(API_Dot2_RemoveExpiredSCCCert, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2Time64 exp;

  /*
   * SCC 인증서를 등록한다.
   */
  uint8_t rca_cert[kDot2CertSize_Max];
  size_t rca_cert_size;
  rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
  ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
  ASSERT_EQ(Dot2_AddSCCCert(rca_cert, rca_cert_size), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);

  /*
   * API 호출시 만기시각을 SCC 인증서 유효기간 만기 이전으로 전달하면 SCC 인증서가 삭제되지 않는 것을 확인한다.
   */
  exp = g_tv_rca_cert_valid_end - 1;
  Dot2_RemoveExpiredSCCCert(exp);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);

  /*
   * API 호출시 만기시각을 SCC 인증서 유효기간 만기시각으로 전달하면 SCC 인증서가 삭제되지 않는 것을 확인한다.
   */
  exp = g_tv_rca_cert_valid_end;
  Dot2_RemoveExpiredSCCCert(exp);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);

  /*
   * API 호출시 만기시각을 SCC 인증서 유효기간 이후로 전달하면 SCC 인증서가 삭제되는 것을 확인한다.
   */
  exp = g_tv_rca_cert_valid_end + 1;
  Dot2_RemoveExpiredSCCCert(exp);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);

  /*
   * SCC 인증서를 다시 등록한다.
   */
  ASSERT_EQ(Dot2_AddSCCCert(rca_cert, rca_cert_size), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);

  SAVE_TEST_START_TIME;

  /*
   * 현재시각이 SCC 인증서 만기시각(2091-03-27 05:48:01 UTC) 이전이면, API 호출 시 만기시각을 0으로 전달하면 SCC 인증서가 삭제되지 않는 것을 확인한다.
   */
  system("date -s '2091-03-27 05:47:30'");
  Dot2_RemoveExpiredSCCCert(0);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 1u);

  /*
   * 현재시각이 SCC 인증서 만기시각 이후이면, API 호출 시 만기시각을 0으로 전달하면 SCC 인증서가 삭제되는 것을 확인한다.
   */
  system("date -s '2091-03-27 05:48:30'");
  Dot2_RemoveExpiredSCCCert(0);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}

