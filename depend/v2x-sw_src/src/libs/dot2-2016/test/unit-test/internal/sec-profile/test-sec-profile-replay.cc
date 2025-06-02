/** 
  * @file 
  * @brief Security profile 내 SPDU replay 체크 기능에 대한 단위테스트를 구현한 파일
  * @date 2021-09-14 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-profile/dot2-sec-profile.h"
#include "sec-profile/dot2-sec-profile-inline.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


extern struct Dot2Test_SecProfileReplayTestVector g_replay_check_test_vector[];


/**
 * @brief Security profile 내에 Replay 체크 정보가 정상적으로 저장되는 것을 확인한다 - dot2_AddSecProfileReplayCheckEntry()
 */
TEST(SEC_PROFILE_REPLAY_CHECK, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SecProfile profile{};
  struct Dot2SecProfileEntry *profile_entry;
  struct Dot2SecProfileReplayCheckList *replay_check_list;

  /*
   * Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&profile);
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  profile_entry = dot2_FindSecProfile(profile.psid);
  ASSERT_TRUE(profile_entry != nullptr);
  replay_check_list = &(profile_entry->replay_check_list);

  /*
   * [TEST] Security profile에 replay 정보를 추가하면 성공적으로 저장되는 것을 확인한다.
   */
  Dot2Time64 spdu_gen_time = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_SPDU_1_GEN_TIME;
  Dot2Time64 spdu_rx_time = spdu_gen_time + 1000ULL;
  struct Dot2Signature spdu_sign = g_replay_check_test_vector[0].spdu_1_sign;
  ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, spdu_rx_time, spdu_gen_time, &spdu_sign);
  ASSERT_EQ(ret, kDot2Result_Success);
  ASSERT_EQ(replay_check_list->entry_num, 1U);
  struct Dot2SecProfileReplayCheckEntry *entry = TAILQ_FIRST(&(replay_check_list->head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_EQ(entry->spdu_gen_time, spdu_gen_time);
  ASSERT_EQ(entry->entry_gen_time, spdu_rx_time);
  ASSERT_TRUE(Dot2Test_CompareOctets(&(entry->spdu_sign), &spdu_sign, sizeof(spdu_sign)));

  Dot2_Release();
}


/**
 * @brief Security profile 내 Replay 체크 리스트가 가득 찼을 때의 동작을 확인한다 - dot2_AddSecProfileReplayCheckEntry()
 */
TEST(SEC_PROFILE_REPLAY_CHECK, QUEUE_FULL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SecProfile profile{};
  struct Dot2SecProfileEntry *profile_entry;
  struct Dot2SecProfileReplayCheckList *replay_check_list;
  struct Dot2Signature spdu_sign = g_replay_check_test_vector[0].spdu_1_sign;

  /*
   * Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&profile);
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  profile_entry = dot2_FindSecProfile(profile.psid);
  ASSERT_TRUE(profile_entry != nullptr);
  replay_check_list = &(profile_entry->replay_check_list);


  /*
   * 각 SPDU 정보는 생성시각/수신시각을 다르게 해서 저장한다.
   * 서명정보는 코드 작성의 번거로움을 피하기 위해 그냥 동일하게 사용하며, 결과 확인을 위해서는 생성시각만을 비교한다.
   */


  /*
   * 첫번째 SPDU 정보를 저장한다.
   */
  Dot2Time64 first_spdu_gen_time = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_SPDU_1_GEN_TIME;
  Dot2Time64 first_spdu_rx_time = first_spdu_gen_time + 1000ULL;
  ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, first_spdu_rx_time, first_spdu_gen_time, &spdu_sign);
  ASSERT_EQ(ret, kDot2Result_Success);
  ASSERT_EQ(replay_check_list->entry_num, 1U);

  /*
   * 두번째 SPDU 정보를 저장한다.
   */
  Dot2Time64 second_spdu_gen_time = first_spdu_gen_time + 100000ULL;
  Dot2Time64 second_spdu_rx_time = second_spdu_gen_time + 1000ULL;
  ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, second_spdu_rx_time, second_spdu_gen_time, &spdu_sign);
  ASSERT_EQ(ret, kDot2Result_Success);
  ASSERT_EQ(replay_check_list->entry_num, 2U);

  /*
   * 리스트가 가득 찰 때까지 SPDU 정보를 저장한다.
  */
  Dot2Time64 spdu_gen_time, spdu_rx_time;
  for (unsigned int i = 2; i < kDot2SecProfileReplayCheckEntryNum_Max; i++) {
    spdu_gen_time = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_SPDU_2_GEN_TIME + (i*100000ULL);
    spdu_rx_time = spdu_gen_time + 1000ULL;
    ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, spdu_rx_time, spdu_gen_time, &spdu_sign);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_EQ(replay_check_list->entry_num, i + 1);
  }
  ASSERT_EQ(replay_check_list->entry_num, kDot2SecProfileReplayCheckEntryNum_Max);

  /*
   * 리스트 내 첫번째와 두번째, 마지막 SPDU 정보가 제대로 저장되어 있는지 확인한다.
   */
  struct Dot2SecProfileReplayCheckEntry *first_entry = TAILQ_FIRST(&(replay_check_list->head));
  struct Dot2SecProfileReplayCheckEntry *second_entry = TAILQ_NEXT(first_entry, entries);
  struct Dot2SecProfileReplayCheckEntry *last_entry = TAILQ_LAST(&(replay_check_list->head), Dot2SecProfileReplayCheckEntryHead);
  ASSERT_TRUE(first_entry != nullptr);
  ASSERT_TRUE(second_entry != nullptr);
  ASSERT_TRUE(last_entry != nullptr);
  ASSERT_EQ(first_entry->spdu_gen_time, first_spdu_gen_time);
  ASSERT_EQ(first_entry->entry_gen_time, first_spdu_rx_time);
  ASSERT_EQ(second_entry->spdu_gen_time, second_spdu_gen_time);
  ASSERT_EQ(second_entry->entry_gen_time, second_spdu_rx_time);
  ASSERT_EQ(last_entry->spdu_gen_time, spdu_gen_time);
  ASSERT_EQ(last_entry->entry_gen_time, spdu_rx_time);

  /*
   * [TEST] 정보를 추가로 등록하면 가장 오래된 첫번째 SPDU 정보가 삭제되고 새로운 정보가 리스트 마지막에 추가되는 것을 확인한다.
   */
  Dot2Time64 last_spdu_gen_time = spdu_gen_time + 100000ULL;
  Dot2Time64 last_spdu_rx_time = last_spdu_gen_time + 1000ULL;
  ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, last_spdu_rx_time, last_spdu_gen_time, &spdu_sign);
  ASSERT_EQ(ret, kDot2Result_Success);
  ASSERT_EQ(replay_check_list->entry_num, kDot2SecProfileReplayCheckEntryNum_Max);
  first_entry = TAILQ_FIRST(&(replay_check_list->head));
  last_entry = TAILQ_LAST(&(replay_check_list->head), Dot2SecProfileReplayCheckEntryHead);
  ASSERT_TRUE(first_entry != nullptr);
  ASSERT_TRUE(last_entry != nullptr);
  ASSERT_EQ(first_entry->spdu_gen_time, second_spdu_gen_time); /// 두번째 SPDU 정보가 리스트의 가장 앞에 있는 것을 확인
  ASSERT_EQ(first_entry->entry_gen_time, second_spdu_rx_time); /// 두번째 SPDU 정보가 리스트의 가장 앞에 있는 것을 확인
  ASSERT_EQ(last_entry->spdu_gen_time, last_spdu_gen_time);
  ASSERT_EQ(last_entry->entry_gen_time, last_spdu_rx_time);

  Dot2_Release();
}


/**
 * @brief Replay 체크 엔트리의 동일 SPDU 정보 여부 체크 기능을 확인한다 - dot2_CheckIdenticalSecProfileReplayCheckEntry()
 */
TEST(SEC_PROFILE_REPLAY_CHECK, CHECK_IDENTICAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SecProfile profile{};
  struct Dot2SecProfileEntry *profile_entry;
  struct Dot2SecProfileReplayCheckList *replay_check_list;
  struct Dot2SecProfileReplayCheckEntry *replay_check_entry;
  Dot2Time64 spdu_1_gen_time, spdu_2_gen_time, spdu_1_rx_time;
  struct Dot2Signature *spdu_1_sign, *spdu_2_sign;

  /*
   * Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&profile);
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  profile_entry = dot2_FindSecProfile(profile.psid);
  ASSERT_TRUE(profile_entry != nullptr);
  replay_check_list = &(profile_entry->replay_check_list);

  /*
   * [TEST] 각 테스트벡터에 대해 동일 SPDU 여부 체크 결과가 정확한지 확인한다.
   */
  for (unsigned int i = 0; i < SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_TEST_CNT; i++)
  {
    // 첫번째 SPDU 정보 엔트리 저장
    spdu_1_gen_time = g_replay_check_test_vector[i].spdu_1_gen_time;
    spdu_1_rx_time = spdu_1_gen_time + 1000ULL;
    spdu_1_sign = &(g_replay_check_test_vector[i].spdu_1_sign);
    ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, spdu_1_rx_time, spdu_1_gen_time, spdu_1_sign);
    ASSERT_EQ(ret, kDot2Result_Success);
    replay_check_entry = TAILQ_FIRST(&(replay_check_list->head));

    // 두번째 SPDU의 정보와 첫번째 SPDU 정보 엔트리 내 정보의 동일 여부 비교 결과가 정확한지 확인한다.
    spdu_2_gen_time = g_replay_check_test_vector[i].spdu_2_gen_time;
    spdu_2_sign = &(g_replay_check_test_vector[i].spdu_2_sign);
    bool identical = dot2_CheckIdenticalSecProfileReplayCheckEntry(replay_check_entry, spdu_2_gen_time, spdu_2_sign);
    ASSERT_EQ(identical, g_replay_check_test_vector[i].identical);

    // 다음 테스트를 위해 리스트를 비운다.
    dot2_FlushSecProfileReplayCheckList(replay_check_list);
  }

  Dot2_Release();
}


/**
 * @brief Security profile 내 Replay 체크 리스트 내에서 동일 정보를 찾는 기능이 정상적으로 동작하는지 확인한다.
 */
TEST(SEC_PROFILE_REPLAY_CHECK, FIND_IDENTICAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SecProfile profile{};
  struct Dot2SecProfileEntry *profile_entry;
  struct Dot2SecProfileReplayCheckList *replay_check_list;
  struct Dot2SecProfileReplayCheckEntry *replay_check_entry;
  Dot2Time64 valid_period = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_VALID_PERIOD;

  /*
   * Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&profile);
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  profile_entry = dot2_FindSecProfile(profile.psid);
  ASSERT_TRUE(profile_entry != nullptr);
  replay_check_list = &(profile_entry->replay_check_list);

  /*
   * replay 체크 리스트에 중복 아닌 SPDU 정보들을 최대한 저장한다.
   */
  Dot2Time64 spdu_gen_time, spdu_rx_time;
  Dot2Time64 first_spdu_gen_time = g_replay_check_test_vector[0].spdu_1_gen_time;
  Dot2Time64 first_spdu_rx_time = first_spdu_gen_time + 1000ULL;
  struct Dot2Signature *spdu_sign = &(g_replay_check_test_vector[0].spdu_1_sign);
  for (unsigned int i = 0; i < kDot2SecProfileReplayCheckEntryNum_Max; i++) {
    spdu_rx_time = first_spdu_rx_time + (i * 1000ULL);
    spdu_gen_time = first_spdu_gen_time + (i * 1000ULL);
    ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, spdu_rx_time, spdu_gen_time, spdu_sign);
    ASSERT_EQ(ret, kDot2Result_Success);
  }
  ASSERT_EQ(replay_check_list->entry_num, kDot2SecProfileReplayCheckEntryNum_Max);

  /*
   * [TEST1] 동일한 SPDU에 대한 정보를 리스트에서 탐색했을 때 정상적으로 찾아지는 것을 확인한다.
   */
  Dot2Time64 identical_spdu_gen_time = first_spdu_gen_time + (30 * 1000ULL); // 31번째 SPDU와 동일한 SPDU를 탐색에 사용한다.
  spdu_rx_time += 1000ULL;
  replay_check_entry = dot2_FindIdenticalSPDUInSecProfileReplayCheckList(replay_check_list,
                                                                         spdu_rx_time,
                                                                         identical_spdu_gen_time,
                                                                         spdu_sign,
                                                                         valid_period);
  ASSERT_TRUE(replay_check_entry != nullptr);

  /*
   * [TEST2] 동일하지 않은 SPDU(생성시각이 다른)에 대한 정보를 리스트에서 탐색했을 때에는 찾지 못하는 것을 확인한다.
   */
  Dot2Time64 diff_spdu_gen_time = first_spdu_gen_time + (kDot2SecProfileReplayCheckEntryNum_Max * 1000ULL); // 리스트에 저장된 적 없는 SPDU를 탐색에 사용한다.
  spdu_rx_time += 1000ULL;
  replay_check_entry = dot2_FindIdenticalSPDUInSecProfileReplayCheckList(replay_check_list,
                                                                         spdu_rx_time,
                                                                         diff_spdu_gen_time,
                                                                         spdu_sign,
                                                                         valid_period);
  ASSERT_TRUE(replay_check_entry == nullptr);

  Dot2_Release();
}


/**
 * @brief Security profile 내 Replay 체크 리스트 내 엔트리 만기 기능을 확인한다 - dot2_FindIdenticalSPDUInSecProfileReplayCheckList()
 */
TEST(SEC_PROFILE_REPLAY_CHECK, ENTRY_EXPIRATION)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2SecProfile profile{};
  struct Dot2SecProfileEntry *profile_entry;
  struct Dot2SecProfileReplayCheckList *replay_check_list;
  struct Dot2SecProfileReplayCheckEntry *replay_check_entry;
  Dot2Time64 valid_period = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_VALID_PERIOD;

  /*
   * Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&profile);
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  profile_entry = dot2_FindSecProfile(profile.psid);
  ASSERT_TRUE(profile_entry != nullptr);
  replay_check_list = &(profile_entry->replay_check_list);

  /*
   * replay 체크 리스트에 SPDU 정보를 저장한다.
   */
  Dot2Time64 spdu_gen_time = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY_SPDU_1_GEN_TIME;
  Dot2Time64 spdu_rx_time = spdu_gen_time + 1000ULL;
  struct Dot2Signature *spdu_sign = &(g_replay_check_test_vector[0].spdu_1_sign);
  ret = dot2_AddSecProfileReplayCheckEntry(replay_check_list, spdu_rx_time, spdu_gen_time, spdu_sign);
  ASSERT_EQ(ret, kDot2Result_Success);

  /*
   * [TEST1] SPDU 정보 엔트리 유효기간이 만기되기 전에 동일한 SPDU 정보를 리스트에서 탐색하면 동일 정보가 존재한다고 리턴되는 것을 확인한다.
   */
  replay_check_entry = dot2_FindIdenticalSPDUInSecProfileReplayCheckList(replay_check_list,
                                                                         spdu_rx_time + valid_period, /// 유효기간 만료 전
                                                                         spdu_gen_time,
                                                                         spdu_sign,
                                                                         valid_period);
  ASSERT_TRUE(replay_check_entry != nullptr);
  ASSERT_EQ(replay_check_list->entry_num, 1U); // 기존 정보가 그대로 유지되는 것을 확인한다.

  /*
   * [TEST2] SPDU 정보 엔트리 유효기간 자체가 현재시각보다 클때 동일한 SPDU 정보를 리스트에서 탐색하면 동일 정보가 존재한다고 리턴되는 것을 확인한다.
   *         유효기간 자체가 현재시각보다 길면, 저장된 SPDU 정보는 그 어떤 것도 만료될 수 없다.
   *         일반적으로 현실 세계에서, 유효기간을 이렇게 크게 줄 경우는 없을 것이다. 현재 시각 자체가 이미 꽤 큰 값이므로.
   */
  replay_check_entry = dot2_FindIdenticalSPDUInSecProfileReplayCheckList(replay_check_list,
                                                                         spdu_rx_time,
                                                                         spdu_gen_time,
                                                                         spdu_sign,
                                                                         spdu_rx_time + 1); /// 유효기간 자체가 현재시각보다 큼
  ASSERT_TRUE(replay_check_entry != nullptr);
  ASSERT_EQ(replay_check_list->entry_num, 1U); // 기존 정보가 그대로 유지되는 것을 확인한다.

  /*
   * [TEST3] SPDU 정보 엔트리 유효기간이 만기된 후에 동일한 SPDU 정보를 리스트에서 탐색하면 동일 정보가 존재하지 않는다고 리턴되는 것을 확인한다.
   *         (만료되어 삭제되므로)
   */
  replay_check_entry = dot2_FindIdenticalSPDUInSecProfileReplayCheckList(replay_check_list,
                                                                         spdu_rx_time + valid_period + 1, /// 유효기간 만료 후
                                                                         spdu_gen_time,
                                                                         spdu_sign,
                                                                         valid_period);
  ASSERT_TRUE(replay_check_entry == nullptr);
  ASSERT_EQ(replay_check_list->entry_num, 0U); // 기존 정보가 삭제된 것을 확인한다.

  Dot2_Release();
}
