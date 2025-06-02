/** 
 * @file
 * @brief Dot2_AddSecProfile() API에 대한 단위테스트를 정의한 파일
 * @date 2020-05-16
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
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_AddSecProfile() API의 기본 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정

  /*
   * Security profile 추가 시 정상적으로 추가되는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(SEC_PROFILE_PSID);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.psid, SEC_PROFILE_PSID);
  ASSERT_EQ(sec_profile_entry->profile.tx.gen_time_hdr, SEC_PROFILE_TX_GEN_TIME_HDR_PRESENT);
  ASSERT_EQ(sec_profile_entry->profile.tx.gen_location_hdr, SEC_PROFILE_TX_EXP_TIME_HDR_PRESENT);
  ASSERT_EQ(sec_profile_entry->profile.tx.exp_time_hdr, SEC_PROFILE_TX_GEN_LOCATION_HDR_PRESENT);
  ASSERT_EQ(sec_profile_entry->profile.tx.spdu_lifetime, SEC_PROFILE_TX_SPDU_LIFETIME);
  ASSERT_EQ(sec_profile_entry->profile.tx.min_inter_cert_time, SEC_PROFILE_TX_MIN_INTER_CERT_TIME);
  ASSERT_EQ(sec_profile_entry->profile.tx.sign_type, SEC_PROFILE_TX_SIGN_TYPE);
  ASSERT_EQ(sec_profile_entry->profile.tx.ecp_format, SEC_PROFLIE_TX_ECP_FORMAT);
  ASSERT_EQ(sec_profile_entry->profile.tx.interval, SEC_PROFILE_TX_SIGNINIG_INTERNVAL);
  ASSERT_EQ(sec_profile_entry->profile.rx.verify_data, SEC_PROFILE_RX_VERIFY_DATA);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.replay, SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_time_in_past, SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_IN_PAST);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.validity_period, SEC_PROFILE_RX_RELEVANCE_CHECK_VALIDITY_PERIOD);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_time_in_future, SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_IN_FUTURE);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.acceptable_future_data_period, SEC_PROFILE_RX_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_time_src, SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_SRC);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.exp_time, SEC_PROFILE_RX_RELEVANCE_CHECK_EXP_TIME);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.exp_time_src, SEC_PROFILE_RX_RELEVANCE_CHECK_EXP_TIME_SRC);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_location_distance, SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION_DISTANCE);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.valid_distance, SEC_PROFILE_RX_RELEVANCE_CHECK_VALID_DISTANCE);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_location_src, SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION_SRC);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.cert_expiry, SEC_PROFILE_RX_RELEVANCE_CHECK_CERT_EXPIRY);
  ASSERT_EQ(sec_profile_entry->profile.rx.consistency_check.gen_location, SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION);
  ASSERT_EQ(sec_profile_entry->profile.rx.consistency_check.overdue_crl_tolerance, SEC_PROFILE_RX_RELEVANCE_CHECK_OVERDUE_CRL_TOLERANCE);
  ASSERT_EQ(sec_profile_entry->last_cert_sign_time, 0ULL); // 내부정보가 초기화 되었음을 확인
  ASSERT_EQ(sec_profile_entry->replay_check_list.entry_num, 0U); // 내부정보가 초기화 되었음을 확인

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 NULL 파라미터를 전달하면 정상적으로 에러 처리하는 것을 확인한다.
 */
TEST(Dot2_AddSecProfile, NULL_PARAMETER)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfile profile{};
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정

  /*
   * Null 파라미터 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_AddSecProfile(nullptr), -kDot2Result_SECPROFILE_NullParameters);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 0U);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 PSID 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_PSID)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 최소 PSID 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = kDot2PSID_Min;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(kDot2PSID_Min);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  /*
   * 최대 PSID 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = kDot2PSID_Max;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(kDot2PSID_Max);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  /*
   * 유효하지 않은 PSID 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = kDot2PSID_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidPSID);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(kDot2PSID_Max + 1);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 Min inter cert time 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_MIN_INTER_CERT_TIME)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 최소 Min inter cert time 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  profile.tx.min_inter_cert_time = kDot2SecProfileInterCertTime_Min;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.tx.min_inter_cert_time, kDot2SecProfileInterCertTime_Min);

  /*
   * 최대 Min inter cert time 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.tx.min_inter_cert_time = kDot2SecProfileInterCertTime_Max;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.tx.min_inter_cert_time, kDot2SecProfileInterCertTime_Max);

  /*
   * 유효하지 않은 Min inter cert time 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.tx.min_inter_cert_time = kDot2SecProfileInterCertTime_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidMinimumInterCertTime);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 signature type 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_SIGNATURE_TYPE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 최소 signature type 값 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  profile.tx.sign_type = kDot2SecProfileSign_Min;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.tx.sign_type, kDot2SecProfileSign_Min);

  /*
   * 최대 signature type 값 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.tx.sign_type = kDot2SecProfileSign_Max;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.tx.sign_type, kDot2SecProfileSign_Max);

  /*
   * 유효하지 않은 signature type 값 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.tx.sign_type = kDot2SecProfileSign_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSignatureType);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 EC point format 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_EC_POINT_FORMAT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 표준에 따라 지원하지 않는 EC point format (Uncompressed) 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Uncompressed;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_NotSupportedEccCurvePointType);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 0U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * 유효한 EC point format (Compressed) 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.tx.ecp_format, kDot2SecProfileEcPointFormat_Compressed);

  /*
   * 유효하지 않은 EC point format 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidECPointType);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 Generation time source 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_GEN_TIME_SRC)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 최소 Generation time source 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Min;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_time_src, kDot2RelevanceTimeSource_Min);

  /*
   * 최대 Generation time source 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_time_src, kDot2RelevanceTimeSource_Max);

  /*
   * gen_time_in_past = true, gen_time_in_future = true 일 경우, 유효하지 않은 Generation time source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.rx.relevance_check.gen_time_in_past = true;
  profile.rx.relevance_check.gen_time_in_future = true;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUGenerationTimeSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * gen_time_in_past = true, gen_time_in_future = false 일 경우, 유효하지 않은 Generation time source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 3;
  profile.rx.relevance_check.gen_time_in_past = true;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUGenerationTimeSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(3);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * gen_time_in_past = false, gen_time_in_future = true 일 경우, 유효하지 않은 Generation time source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 4;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = true;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUGenerationTimeSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(4);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * gen_time_in_past = false, gen_time_in_future = false 일 경우, 유효하지 않은 Generation time source 전달 시에도 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 5;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 3U);
  sec_profile_entry = dot2_FindSecProfile(5);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 Expiration time source 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_EXP_TIME_SRC)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 최소 Expiration time source 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_Min;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.exp_time_src, kDot2RelevanceTimeSource_Min);

  /*
   * 최대 Expiration time source 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_Max;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.exp_time_src, kDot2RelevanceTimeSource_Max);

  /*
   * exp_time = true인 경우, 유효하지 않은 Expiration time source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.rx.relevance_check.exp_time = true;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUExpiryTimeSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * exp_time = false인 경우, 유효하지 않은 Expiration time source 전달 시에도 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 3;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 3U);
  sec_profile_entry = dot2_FindSecProfile(3);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 Generation location source 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, PARAM_CHECK_GEN_LOCATION_SRC)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 최소 Generation location source 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_Min;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_location_src, kDot2ConsistencyLocationSource_Min);

  /*
   * 최대 Generation location source 전달 시 정상적으로 추가되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_Max;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry != nullptr);
  ASSERT_EQ(sec_profile_entry->profile.rx.relevance_check.gen_location_src, kDot2ConsistencyLocationSource_Max);

  /*
   * gen_location_distance = true인 경우, 유효하지 않은 Generation location source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.rx.relevance_check.gen_location_distance = true;
  profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUGenerationLocationSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * gen_location_distance = false인 경우, 유효하지 않은 Generation location source 전달 시에도 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 3;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 3U);
  sec_profile_entry = dot2_FindSecProfile(3);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 전달되는 verify_data 값에 따른 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, VERIFY_DATA)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * verify_data == true이면, 유효하지 않은 Generation time source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 1;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUGenerationTimeSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 0U);
  sec_profile_entry = dot2_FindSecProfile(1);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * verify_data == true이면, 유효하지 않은 Expiration time source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 2;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUExpiryTimeSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 0U);
  sec_profile_entry = dot2_FindSecProfile(2);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * verify_data == true이면, 유효하지 않은 Generation location source 전달 시 정상적으로 에러 처리하는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 3;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_InvalidSPDUGenerationLocationSource);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 0U);
  sec_profile_entry = dot2_FindSecProfile(3);
  ASSERT_TRUE(sec_profile_entry == nullptr);

  /*
   * verify_data == false이면, 유효하지 않은 Generation time source 전달 시에도 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 4;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(4);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  /*
   * verify_data == true이면, 유효하지 않은 Expiration time source 전달 시에도 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 5;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 2U);
  sec_profile_entry = dot2_FindSecProfile(5);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  /*
   * verify_data == true이면, 유효하지 않은 Generation location source 전달 시에도 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 6;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_Max + 1;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 3U);
  sec_profile_entry = dot2_FindSecProfile(6);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 중복된 PSID 에 대한 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, DUPLICATE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * 첫번째 등록 시 정상적으로 등록되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  /*
   * 동일한 PSID로 등록 시 정상적으로 에러 처리 되는 것을 확인한다.
   * - 기존 profile은 그대로 유지되는 것을 확인한다.
   */
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정
  profile.psid = 0;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_SameSecProfileInTable);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, 1U);
  sec_profile_entry = dot2_FindSecProfile(0);
  ASSERT_TRUE(sec_profile_entry != nullptr);

  Dot2_Release();
}


/**
 * @brief Dot2_AddSecProfile() API 호출 시 Security profile 테이블이 가득차는 경우에 대한 동작을 확인한다.
 */
TEST(Dot2_AddSecProfile, TABLE_FULL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SecProfileEntry *sec_profile_entry;
  struct Dot2SecProfile profile{};
  Dot2Test_SetSecProfile(&profile); // 테스트용 기본(정상) 값으로 설정

  /*
   * 등록 가능한 최대 개수만큼 등록한다.
   */
  for (unsigned int i = 0; i < kDot2SecProfileEntryNum_Max; i++) {
    profile.psid = i;
    ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, i + 1);
    sec_profile_entry = dot2_FindSecProfile(i);
    ASSERT_TRUE(sec_profile_entry != nullptr);
  }
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, kDot2SecProfileEntryNum_Max); // 최대 개수만큼 저장되어 있는 것을 확인한다.

  /*
   * 추가 등록 시 정상적으로 에러 처리 되는 것을 확인한다.
   */
  profile.psid = 100;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), -kDot2Result_SECPROFILE_TooManySecProfileInTable);
  ASSERT_EQ(g_dot2_mib.sec_profile_table.entry_num, kDot2SecProfileEntryNum_Max);

  Dot2_Release();
}
