/** 
 * @file
 * @brief Security profile 탐색 기능에 대한 단위테스트
 * @date 2020-05-22
 * @author gyun
 *
 * 본 단위테스트는 다음을 포함한다. \n
 *  - 테이블에 등록되어 있는 Psid 탐색 시의 동작 \n
 *  - 테이블에 등록되어 있지 않은 Psid 탐색 시의 동작 \n
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


/**
 * @brief "Security profile" 탐색 기본 동작을 확인한다.
 *
 * Security profile 테이블에 등록되어 있는 PSID로 탐색 시, 잘 탐색되는 것을 확인한다.
 */
 TEST(FIND_SEC_PROFILE, NORMAL)
{
   ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
   * 랜덤 시드값 설정
   */
  struct timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  srand(ts.tv_sec);

#define TEST_CNT 15
  struct Dot2SecProfile sample[TEST_CNT];

  /*
   * Security profile 등록
   */
  for (unsigned int i = 0; i < TEST_CNT; i++) {
    Dot2Test_SetSecProfile(&sample[i]);
    sample[i].psid = rand() % (kDot2PSID_Max + 1);
    sample[i].tx.gen_time_hdr = ((rand() % 2) == 1) ? true : false;
    sample[i].tx.gen_time_hdr = ((rand() % 2) == 1) ? true : false;
    sample[i].tx.exp_time_hdr = ((rand() % 2) == 1) ? true : false;
    sample[i].tx.spdu_lifetime = (Dot2Time64)rand();
    sample[i].tx.min_inter_cert_time = ((Dot2Time64)rand() % kDot2SecProfileInterCertTime_Max);
    sample[i].tx.sign_type = kDot2SecProfileSign_Compressed;
    sample[i].tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
    sample[i].tx.interval = rand();
    sample[i].rx.verify_data = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.replay = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.gen_time_in_past = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.validity_period = (Dot2Time64)rand();
    sample[i].rx.relevance_check.gen_time_in_future = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.acceptable_future_data_period = (Dot2Time64)rand();
    sample[i].rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
    sample[i].rx.relevance_check.exp_time = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
    sample[i].rx.relevance_check.gen_location_distance = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.valid_distance = rand();
    sample[i].rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_SecurityHeader;
    sample[i].rx.relevance_check.cert_expiry = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.consistency_check.gen_location = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.consistency_check.overdue_crl_tolerance = rand();
    ASSERT_EQ(Dot2_AddSecProfile(&sample[i]), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, i + 1);
  }

  /*
   * 등록된 각 PSID에 대한 Security profile 탐색
   */
  struct Dot2SecProfileEntry *profile_entry;
  for (int i = 0; i < TEST_CNT; i++) {
    profile_entry = dot2_FindSecProfile(sample[i].psid);
    ASSERT_TRUE(profile_entry != nullptr);
    ASSERT_EQ(profile_entry->profile.psid, sample[i].psid);
    ASSERT_EQ(profile_entry->profile.tx.gen_time_hdr, sample[i].tx.gen_time_hdr);
    ASSERT_EQ(profile_entry->profile.tx.gen_location_hdr, sample[i].tx.gen_location_hdr);
    ASSERT_EQ(profile_entry->profile.tx.exp_time_hdr, sample[i].tx.exp_time_hdr);
    ASSERT_EQ(profile_entry->profile.tx.spdu_lifetime, sample[i].tx.spdu_lifetime);
    ASSERT_EQ(profile_entry->profile.tx.min_inter_cert_time, sample[i].tx.min_inter_cert_time);
    ASSERT_EQ(profile_entry->profile.tx.sign_type, sample[i].tx.sign_type);
    ASSERT_EQ(profile_entry->profile.tx.ecp_format, sample[i].tx.ecp_format);
    ASSERT_EQ(profile_entry->profile.tx.interval, sample[i].tx.interval);
    ASSERT_EQ(profile_entry->profile.rx.verify_data, sample[i].rx.verify_data);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.replay, sample[i].rx.relevance_check.replay);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.gen_time_in_past, sample[i].rx.relevance_check.gen_time_in_past);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.validity_period, sample[i].rx.relevance_check.validity_period);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.gen_time_in_future, sample[i].rx.relevance_check.gen_time_in_future);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.acceptable_future_data_period, sample[i].rx.relevance_check.acceptable_future_data_period);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.gen_time_src, sample[i].rx.relevance_check.gen_time_src);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.exp_time, sample[i].rx.relevance_check.exp_time);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.exp_time_src, sample[i].rx.relevance_check.exp_time_src);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.gen_location_distance, sample[i].rx.relevance_check.gen_location_distance);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.valid_distance, sample[i].rx.relevance_check.valid_distance);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.gen_location_src, sample[i].rx.relevance_check.gen_location_src);
    ASSERT_EQ(profile_entry->profile.rx.relevance_check.cert_expiry, sample[i].rx.relevance_check.cert_expiry);
    ASSERT_EQ(profile_entry->profile.rx.consistency_check.gen_location, sample[i].rx.consistency_check.gen_location);
    ASSERT_EQ(profile_entry->profile.rx.consistency_check.overdue_crl_tolerance, sample[i].rx.consistency_check.overdue_crl_tolerance);
  }

  Dot2_Release();
}


/**
 * @brief 등록되지 않은 PSID로 탐색 시, 탐색 실패하는 것을 확인한다.
 */
TEST(FIND_SEC_PROFILE, NOT_REGISTERED_PSID)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
   * 랜덤 시드값 설정
   */
  struct timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  srand(ts.tv_sec);

#define TEST_CNT 15
  struct Dot2SecProfile sample[TEST_CNT];

  /*
   * Security profile 등록
   */
  for (unsigned int i = 0; i < TEST_CNT; i++) {
    Dot2Test_SetSecProfile(&sample[i]);
    sample[i].psid = i;
    sample[i].tx.gen_time_hdr = ((rand() % 2) == 1) ? true : false;
    sample[i].tx.gen_time_hdr = ((rand() % 2) == 1) ? true : false;
    sample[i].tx.exp_time_hdr = ((rand() % 2) == 1) ? true : false;
    sample[i].tx.spdu_lifetime = (Dot2Time64)rand();
    sample[i].tx.min_inter_cert_time = ((Dot2Time64)rand() % kDot2SecProfileInterCertTime_Max);
    sample[i].tx.sign_type = kDot2SecProfileSign_Compressed;
    sample[i].tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
    sample[i].tx.interval = rand();
    sample[i].rx.verify_data = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.replay = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.gen_time_in_past = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.validity_period = (Dot2Time64)rand();
    sample[i].rx.relevance_check.gen_time_in_future = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.acceptable_future_data_period = (Dot2Time64)rand();
    sample[i].rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
    sample[i].rx.relevance_check.exp_time = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
    sample[i].rx.relevance_check.gen_location_distance = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.relevance_check.valid_distance = rand();
    sample[i].rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_SecurityHeader;
    sample[i].rx.relevance_check.cert_expiry = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.consistency_check.gen_location = ((rand() % 2) == 1) ? true : false;
    sample[i].rx.consistency_check.overdue_crl_tolerance = rand();
    ASSERT_EQ(Dot2_AddSecProfile(&sample[i]), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, i + 1);
  }

  /*
   * 등록되지 않은 PSID에 대한 Security profile 탐색 시 실패하는 것을 확인한다.
   */
  struct Dot2SecProfileEntry *profile_entry;
  for (int i = 0; i < TEST_CNT; i++) {
    profile_entry = dot2_FindSecProfile(200 + i);
    ASSERT_TRUE(profile_entry == nullptr);
  }

  Dot2_Release();
}
