/**
  * @file
  * @brief Dot2_RemoveExpiredCMH() API 동작 단위테스트 구현 파일
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
 * @brief Dot2_RemoveExpiredCMH() API 호출시 어플리케이션 CMH에 대한 동작을 확인한다.
 */
TEST(API_Dot2_RemoveExpiredCMH, APP_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SequentialCMHEntry *cmh_entry[2] = { nullptr, nullptr };

  /*
  * SCC인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_0_SCCCerts();

  /*
   * Application CMHF들을 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_AppCMHFs();
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 2U);
  ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
  ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
  // 첫번째 CMH
  cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.app.head));
  ASSERT_TRUE(cmh_entry[0]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_0_CMHEntry(cmh_entry[0]));
  // 두번째 CMH
  cmh_entry[1] = TAILQ_NEXT(cmh_entry[0], entries);
  ASSERT_TRUE(cmh_entry[1]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_1_CMHEntry(cmh_entry[1]));

  Dot2Time64 exp;
  Dot2Time64 first_cmh_exp = 540171334000000ULL;
  Dot2Time64 second_cmh_exp = 543231334000000ULL;

  /*
   * API 호출시 만기시각을 첫번째 CMH 유효기간 만기 이전으로 전달하면 두 CMH가 모두 삭제되지 않는 것을 확인한다.
   */
  exp = first_cmh_exp - 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 2U);

  /*
   * API 호출시 만기시각을 첫번째 CMH 유효기간 만기시각으로 전달하면 두 CMH가 모두 삭제되지 않는 것을 확인한다.
   */
  exp = first_cmh_exp;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 2U);

  /*
   * API 호출시 만기시각을 첫번째 CMH 유효기간 이후 및 두번째 CMH 유효기간 이전으로 전달하면 첫번째 CMH만 삭제되는 것을 확인한다.
   */
  exp = first_cmh_exp + 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1U);

  /*
   * API 호출시 만기시각을 두번째 CMH 유효기간 만기시각으로 전달하면 두번째 CMH가 삭제되지 않는 것을 확인한다.
   */
  exp = second_cmh_exp;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1U);

  /*
   * API 호출시 만기시각을 두번째 CMH 유효기간 만기시각 이후로 전달하면 두번째 CMH가 삭제되는 것을 확인한다.
   */
  exp = second_cmh_exp + 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 0U);

  /*
   * Application CMHF들을 다시 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_AppCMHFs();
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 2U);
  ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
  ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
  // 첫번째 CMH
  cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.app.head));
  ASSERT_TRUE(cmh_entry[0]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_0_CMHEntry(cmh_entry[0]));
  // 두번째 CMH
  cmh_entry[1] = TAILQ_NEXT(cmh_entry[0], entries);
  ASSERT_TRUE(cmh_entry[1]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_1_CMHEntry(cmh_entry[1]));

  SAVE_TEST_START_TIME;

  /*
   * 현재시각이 첫번째 CMH 만기시각(2021-02-11 23:35:29 UTC) 이전이면, API 호출시 만기시각을 0으로 전달하면 두 CMH가 모두 삭제되지 않는 것을 확인한다.
   */
  system("date -s '2021-02-11 23:35:00'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 2U);

  /*
   * 현재시각이 첫번째 CMH 만기시각 이후 및 두번째 CMH 만기시각(2021-03-19 09:35:29 UTC) 이전이면, API 호출시 만기시각을 0으로 전달하면 첫번째 CMH만 삭제되는 것을 확인한다.
   */
  system("date -s '2021-03-19 09:35:00'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1U);

  /*
   * 현재시각이 두번째 CMH 만기시각 이후이면, API 호출시 만기시각을 0으로 전달하면 두번째 CMH가 삭제되는 것을 확인한다.
   */
  system("date -s '2021-03-19 09:35:30'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 0U);

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}


/**
 * @brief Dot2_RemoveExpiredCMH() API 호출시 어플리케이션 CMH에 대한 동작을 확인한다.
 */
TEST(API_Dot2_RemoveExpiredCMH, PSEUDONYM_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2RotateCMHSetEntry *cmh_entry[1] = { nullptr };

  /*
  * SCC인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_0_SCCCerts();

  /*
   * Pseudonym CMHF를 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_PseudonymCMHFs();
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1U);
  ASSERT_FALSE(g_dot2_mib.cmh_table.pseudonym_id.active_set);;
  ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Pseudonym);
  cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.pseudonym_id.head));
  ASSERT_TRUE(cmh_entry[0]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_0_PseudonymCert_13a_CMHSetEntry(cmh_entry[0]));

  Dot2Time64 exp;
  Dot2Time64 cmh_exp = 538135203000000ULL;

  /*
   * API 호출시 만기시각을 CMH 유효기간 만기 이전으로 전달하면 CMH가 삭제되지 않는 것을 확인한다.
   */
  exp = cmh_exp - 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1U);

  /*
   * API 호출시 만기시각을 CMH 유효기간 만기시각으로 전달하면 CMH가 삭제되지 않는 것을 확인한다.
   */
  exp = cmh_exp;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1U);

  /*
   * API 호출시 만기시각을 CMH 유효기간 이후로 전달하면 CMH가 삭제되는 것을 확인한다.
   */
  exp = cmh_exp + 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 0U);

  /*
   * Pseudonym CMHF를 다시 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_PseudonymCMHFs();
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1U);
  ASSERT_FALSE(g_dot2_mib.cmh_table.pseudonym_id.active_set);;
  ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Pseudonym);
  cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.pseudonym_id.head));
  ASSERT_TRUE(cmh_entry[0]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_0_PseudonymCert_13a_CMHSetEntry(cmh_entry[0]));

  SAVE_TEST_START_TIME;

  /*
   * 현재시각이 CMH 만기시각(2021-01-19 09:59:58 UTC) 이전이면, API 호출시 만기시각을 0으로 전달하면 CMH가 삭제되지 않는 것을 확인한다.
   */
  system("date -s '2021-01-19 09:59:00'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1U);

  /*
   * 현재시각이 CMH 만기시각 이후이면, API 호출시 만기시각을 0으로 전달하면 CMH가 삭제되는 것을 확인한다.
   */
  system("date -s '2021-01-19 10:00:00'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 0U);

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}


/**
 * @brief Dot2_RemoveExpiredCMH() API 호출시 등록인증서 CMH에 대한 동작을 확인한다.
 */
TEST(API_Dot2_RemoveExpiredCMH, ENROL_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SequentialCMHEntry *cmh_entry[1] = { nullptr };

  /*
  * SCC인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_1_SCCCerts();

  /*
   * Enrollment CMHF를 로딩한다.
   */
  Dot2Test_Load_CertBundle_1_EnrolCMHF();
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1U);
  ASSERT_FALSE(g_dot2_mib.cmh_table.enrol.active_cmh);;
  cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.enrol.head));
  ASSERT_TRUE(cmh_entry[0]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_1_EnrolCert_0_CMHEntry(cmh_entry[0]));

  Dot2Time64 exp;
  Dot2Time64 cmh_exp = 775744165000000ULL;

  /*
   * API 호출시 만기시각을 CMH 유효기간 만기 이전으로 전달하면 CMH가 삭제되지 않는 것을 확인한다.
   */
  exp = cmh_exp - 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1U);

  /*
   * API 호출시 만기시각을 CMH 유효기간 만기시각으로 전달하면 CMH가 삭제되지 않는 것을 확인한다.
   */
  exp = cmh_exp;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1U);

  /*
   * API 호출시 만기시각을 CMH 유효기간 만기 이후로 전달하면 CMH가 삭제되는 것을 확인한다.
   */
  exp = cmh_exp + 1ULL;
  Dot2_RemoveExpiredCMH(exp);
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 0U);

  /*
   * 등록 CMHF를 다시 로딩한다.
   */
  Dot2Test_Load_CertBundle_1_EnrolCMHF();
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1U);
  ASSERT_FALSE(g_dot2_mib.cmh_table.enrol.active_cmh);;
  cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.enrol.head));
  ASSERT_TRUE(cmh_entry[0]);
  ASSERT_TRUE(Dot2Test_Check_CertBundle_1_EnrolCert_0_CMHEntry(cmh_entry[0]));

  SAVE_TEST_START_TIME;

  /*
   * 현재시각이 CMH 만기시각(2028-07-31 12:29:20 UTC) 이전이면, API 호출시 만기시각을 0으로 전달하면 CMH가 삭제되지 않는 것을 확인한다.
   */
  system("date -s '2028-07-31 12:29:00'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1U);

  /*
   * 현재시각이 CMH 만기시각 이후이면, API 호출시 만기시각을 0으로 전달하면 CMH가 삭제되는 것을 확인한다.
   */
  system("date -s '2028-07-31 12:30:00'");
  Dot2_RemoveExpiredCMH(0);
  ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 0U);

  WAIT_SYSTIME_RECOVERY;

  Dot2_Release();
}

