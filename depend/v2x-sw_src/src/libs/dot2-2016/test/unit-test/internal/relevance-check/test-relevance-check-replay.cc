/** 
  * @file 
  * @brief SPDU의 Replay 관련 Relevance check 기능에 대한 단위테스트를 구현한 파일
  * @date 2021-09-11
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-profile/dot2-sec-profile.h"
#include "spdu/dot2-spdu.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "test-relevance-check-sample-data.h"


/**
 * @brief SPDU의 Replay 관련 Relevance check 기능(중복 SPDU가 수신되었는지 확인)이 정상적으로 동작하는 것을 확인한다.
 */
TEST(REPLAY_RELEVANCE_CHECK, NORMAL)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry sec_profile_entry{};
  struct Dot2SCCCertInfoEntry pca_entry{}, ica_entry{}, rca_entry{};
  struct Dot2EECertCacheEntry signer_entry{};
  struct Dot2SPDUProcessWorkData work_data{};
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  work_data.parsed = parsed;
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetCertChain_ForRelevanceCheck(&signer_entry, &pca_entry, &ica_entry, &rca_entry);

  unsigned int replay_check_list_cnt = 0;

  /*
   * [TEST1] Security profile이 Replay check를 수행하지 않도록 설정되어 있는 경우, 중복 SPDU이어도 "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, replay_check_list_cnt); // Replay 체크 리스트에 추가되지 않는 것을 확인한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success); // 중복 SPDU여도 성공하는 것을 확인한다.
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, replay_check_list_cnt); // Replay 체크 리스트에 추가되지 않는 것을 확인한다.

  /*
   * [TEST2] 중복 SPDU인 경우 "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_Replay);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, replay_check_list_cnt); // Replay 체크 리스트에 추가되지 않는 것을 확인한다.

  /*
   * [TEST3] 중복 SPDU가 오랜 시간 후에 수신되면(Replay 체크 리스트 정보 만료) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.params.rx_time += (SPDU_RELEVANCE_CHECK_VALIDITY_PERIOD + 1ULL);
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);  // 중복 SPDU여도 성공하는 것을 확인한다.
  replay_check_list_cnt = 1;
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, replay_check_list_cnt); // Replay 체크 리스트 내 기존 엔트리가 모두 만료되어 삭제되고 신규 1개만 존재하는 것을 확인한다.

  /*
   * [TEST4] 중복 SPDU가 아닌 경우(서명 s의 첫번째 바이트 값이 다른 경우) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.s[0]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  /*
   * [TEST5] 중복 SPDU가 아닌 경우(서명 s의 두번째 바이트 값이 다른 경우) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.s[1]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  /*
   * [TEST6] 중복 SPDU가 아닌 경우(서명 Rx의 첫번째 바이트 값이 다른 경우) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.R_r.u.point.u.xy.x[0]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  /*
   * [TEST7] 중복 SPDU가 아닌 경우(서명 Rx의 두번째 바이트 값이 다른 경우) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.R_r.u.point.u.xy.x[1]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  /*
   * [TEST8] 중복 SPDU가 아닌 경우(우연히 서명 s의 첫번째/두번째 바이트 값은 같지만, 다른 바이트 값이 다른 경우) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.s[2]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  /*
   * [TEST9] 중복 SPDU가 아닌 경우(우연히 서명 Rx의 첫번째/두번째 바이트 값은 같지만, 다른 바이트 값이 다른 경우) "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.R_r.u.point.u.xy.x[2]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list));
  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}


/**
 * @brief SPDU의 Replay 관련 Relevance check 기능(중복 SPDU가 수신되었는지 확인)이 SPDU 생성시각에 따라 정상적으로 동작하는 것을 확인한다.
 */
TEST(REPLAY_RELEVANCE_CHECK, SPDU_GEN_TIME)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry sec_profile_entry{};
  struct Dot2SCCCertInfoEntry pca_entry{}, ica_entry{}, rca_entry{};
  struct Dot2EECertCacheEntry signer_entry{};
  struct Dot2SPDUProcessWorkData work_data{};
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  work_data.parsed = parsed;
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetCertChain_ForRelevanceCheck(&signer_entry, &pca_entry, &ica_entry, &rca_entry);

  unsigned int replay_check_list_cnt = 0;

  /*
   * [TEST1] 동일한 생성시각을 갖는 두개의 중복된 SPDU인 경우, "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_Replay);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, replay_check_list_cnt); // Replay 체크 리스트에 추가되지 않는 것을 확인한다.
  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list)); // 다음 테스트를 위해 체크리스트를 비운다.
  replay_check_list_cnt = 0;

  /*
   * [TEST2] 서로 다른 생성시각을 갖는 두개의 SPDU인 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  parsed->spdu.signed_data.gen_time++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list)); // 다음 테스트를 위해 체크리스트를 비운다.
  replay_check_list_cnt = 0;

  /*
   * [TEST3] 생성시각을 갖지 않는 두개의 중복된 SPDU인 경우, "실패"가 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time_present = false;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_Replay);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, replay_check_list_cnt); // Replay 체크 리스트에 추가되지 않는 것을 확인한다.
  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list)); // 다음 테스트를 위해 체크리스트를 비운다.
  replay_check_list_cnt = 0;

  /*
   * [TEST4] 생성시각을 갖지 않는 두개의 중복되지 않는 SPDU인 경우, "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time_present = false;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  work_data.sign.s[0]++;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list)); // 다음 테스트를 위해 체크리스트를 비운다.
  replay_check_list_cnt = 0;

  /*
   * [TEST5] 첫번째 SPDU는 생성시각을 갖고, 두번째 SPDU는 갖지 않을 경우(이는 중복되지 않은 SPDU임), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  parsed->spdu.signed_data.gen_time_present = false;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list)); // 다음 테스트를 위해 체크리스트를 비운다.
  replay_check_list_cnt = 0;

  /*
   * [TEST5] 첫번째 SPDU는 생성시각을 갖지 않고, 두번째 SPDU는 가질 경우(이는 중복되지 않은 SPDU임), "성공"이 반환되는 것을 확인한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  parsed->spdu.signed_data.gen_time_present = false;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  parsed->spdu.signed_data.gen_time_present = true;
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list));

  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}


/**
 * @brief SPDU의 Replay 관련 Relevance check 기능 관련, Replay 체크 리스트가 가득 찼을 때의 동작을 확인한다.
 */
TEST(REPLAY_RELEVANCE_CHECK, REPLAY_CHECK_LIST_FULL)
{
  /*
   * 초기화
   */
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry sec_profile_entry{};
  struct Dot2SCCCertInfoEntry pca_entry{}, ica_entry{}, rca_entry{};
  struct Dot2EECertCacheEntry signer_entry{};
  struct Dot2SPDUProcessWorkData work_data{};
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed != nullptr);
  work_data.parsed = parsed;
  Dot2Test_SetSecurityProfileEntry_ForRelevanceCheck(&sec_profile_entry);
  Dot2Test_SetCertChain_ForRelevanceCheck(&signer_entry, &pca_entry, &ica_entry, &rca_entry);

  unsigned int replay_check_list_cnt = 0;

  /*
   * 첫번째 SPDU에 대한 Relevance check를 수행하여 체크리스트에 추가되도록 한다.
   */
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed);
  sec_profile_entry.profile.rx.relevance_check.replay = true; // Replay 체크하도록 설정한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.

  /*
   * 체크리스트가 가득찰 때까지 중복되지 않는 SPDU 처리를 진행한다.
   */
  struct Dot2SPDUProcessWorkData work_data2;
  struct V2XPacketParseData *parsed2 = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
  ASSERT_TRUE(parsed2 != nullptr);
  work_data2.parsed = parsed2;
  Dot2Test_SetSPDUProcessWorkData_ForRelevanceCheck(&work_data2);
  Dot2Test_SetPacketParseData_ForRelevanceCheck(parsed2);
  for (unsigned int i = 1; i < kDot2SecProfileReplayCheckEntryNum_Max; i++) {
    ASSERT_EQ(dot2_CheckSPDURelevance(&work_data2, &sec_profile_entry, &signer_entry), kDot2Result_Success);
    ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, ++replay_check_list_cnt); // Replay 체크 리스트에 추가되는 것을 확인한다.
    parsed2->spdu.signed_data.gen_time++;
  }
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, kDot2SecProfileReplayCheckEntryNum_Max); // 가득 찬 것을 확인한다.

  /*
   * [TEST1] 새로운 SPDU에 대한 처리를 진행하면, 체크리스트에 추가되는 것을 확인한다 (가장 오래된 엔트리 삭제됨)
   */
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data2, &sec_profile_entry, &signer_entry), kDot2Result_Success);
  ASSERT_EQ(sec_profile_entry.replay_check_list.entry_num, kDot2SecProfileReplayCheckEntryNum_Max); // 엔트리 수가 그대로 인 것을 확인한다.
  ASSERT_EQ(dot2_CheckSPDURelevance(&work_data2, &sec_profile_entry, &signer_entry), -kDot2Result_SPDURelevance_Replay); // 중복체크되는 것을 확인한다.

  dot2_FlushSecProfileReplayCheckList(&(sec_profile_entry.replay_check_list));
  V2X_FreePacketParseData(parsed);
  Dot2_Release();
}
