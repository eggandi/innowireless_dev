/** 
 * @file
 * @brief Security profile에 따라 서명메시지에 수납될 SignerId 유형을 구하는 기능에 대한 단위테스트
 * @date 2020-05-22
 * @author gyun
 *
 * 다음 단위테스트를 포함한다. \n
 *  - Min inter cert time 값 및 호출 시점에 따라 SignerId 값이 정상적으로 반환되는 것을 확인한다. \n
 */

// 시스템 헤더 파일
#include <unistd.h>

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
 * @brief SignerId 확인 기능의 기본 동작을 확인한다.
 */
TEST(SELECT_SIGNER_ID_TYPE, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  Dot2SignerIdType signer_id_type;

  /*----------------------------------------------------------------------------*/
  /* WSA Security profile을 이용한 테스트 (Min inter cert time = 495msec) */
  /*----------------------------------------------------------------------------*/

  struct Dot2SecProfileEntry *wsa_profile_entry;
  struct Dot2SecProfile wsa_profile{};

  /*
   * Min Inter Cert Time을 WSA 기준으로 설정한 Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&wsa_profile);
  wsa_profile.psid = 135;
  wsa_profile.tx.min_inter_cert_time = 495000ULL; // WSA 기준
  ASSERT_EQ(Dot2_AddSecProfile(&wsa_profile), kDot2Result_Success);
  wsa_profile_entry = dot2_FindSecProfile(wsa_profile.psid);
  ASSERT_TRUE(wsa_profile_entry != nullptr);
  ASSERT_EQ(wsa_profile_entry->last_cert_sign_time, 0ULL);

  /*
   * [TEST1] 첫 서명 메시지 생성 시에는 서명자 식별자로 "인증서"가 선택되는 것을 확인한다.
   */
  uint32_t sign_cnt = 1;
  Dot2Time64 now = 1000000ULL;
  Dot2Time64 last_cert_sign_time = now;
  signer_id_type = dot2_SelectSignerIdType(now, wsa_profile_entry);
  ASSERT_EQ(signer_id_type, kDot2SignerId_Certificate);
  ASSERT_EQ(wsa_profile_entry->last_cert_sign_time, last_cert_sign_time);

  /*
   * [TEST2] 최초 서명 후, 5번째 서명시마다(495msec 주기 이상 지연시마다) 서명자 식별자로 "인증서"가 반환되고
   *         그 외에는 "다이제스트"가 반환되는 것을 확인한다.
   */
#define TEST_CNT (1000)
  for (int i = 0; i < TEST_CNT; i++) {
    now += 100000ULL; // 100msec 지연
    sign_cnt++;
    signer_id_type = dot2_SelectSignerIdType(now, wsa_profile_entry);
    if ((sign_cnt % 5) == 1) {
      ASSERT_EQ(signer_id_type, kDot2SignerId_Certificate);
      last_cert_sign_time = now;
    } else {
      ASSERT_EQ(signer_id_type, kDot2SignerId_Digest);
    }
    ASSERT_EQ(wsa_profile_entry->last_cert_sign_time, last_cert_sign_time);
  }


  /*----------------------------------------------------------------------------*/
  /* BSM Security profile을 이용한 테스트 (Min inter cert time = 450msec) */
  /*----------------------------------------------------------------------------*/

  struct Dot2SecProfileEntry *bsm_profile_entry;
  struct Dot2SecProfile bsm_profile{};

  /*
   * Min Inter Cert Time을 BSM 기준으로 설정한 Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&bsm_profile);
  bsm_profile.psid = 32;
  bsm_profile.tx.min_inter_cert_time = 450000ULL; // BSM 기준
  ASSERT_EQ(Dot2_AddSecProfile(&bsm_profile), kDot2Result_Success);
  bsm_profile_entry = dot2_FindSecProfile(bsm_profile.psid);
  ASSERT_TRUE(bsm_profile_entry != nullptr);
  ASSERT_EQ(bsm_profile_entry->last_cert_sign_time, 0ULL);

  /*
   * 첫 서명 메시지 생성 시에는 서명자 식별자로 "인증서"가 선택되는 것을 확인한다.
   */
  sign_cnt = 1;
  now = 1000000ULL;
  last_cert_sign_time = now;
  signer_id_type = dot2_SelectSignerIdType(now, bsm_profile_entry);
  ASSERT_EQ(signer_id_type, kDot2SignerId_Certificate);
  ASSERT_EQ(bsm_profile_entry->last_cert_sign_time, last_cert_sign_time);

  /*
   * 최초 서명 후, 5번째 서명시마다(450msec 주기 이상 지연시마다) 서명자 식별자로 "인증서"가 반환되고
   * 그 외에는 "다이제스트"가 반환되는 것을 확인한다.
   */
#define TEST_CNT (1000)
  for (int i = 0; i < TEST_CNT; i++) {
    now += 100000ULL; // 100msec 지연
    sign_cnt++;
    signer_id_type = dot2_SelectSignerIdType(now, bsm_profile_entry);
    if ((sign_cnt % 5) == 1) {
      ASSERT_EQ(signer_id_type, kDot2SignerId_Certificate);
      last_cert_sign_time = now;
    } else {
      ASSERT_EQ(signer_id_type, kDot2SignerId_Digest);
    }
    ASSERT_EQ(bsm_profile_entry->last_cert_sign_time, last_cert_sign_time);
  }


  /*----------------------------------------------------------------------------*/
  /* 임의의 Security profile을 이용한 테스트 (Min inter cert time = 250msec) */
  /*----------------------------------------------------------------------------*/

  struct Dot2SecProfileEntry *profile_entry;
  struct Dot2SecProfile profile{};

  /*
   * Min Inter Cert Time을 임의로 설정한 Security profile을 등록한다.
   */
  Dot2Test_SetSecProfile(&profile);
  profile.psid = 38;
  profile.tx.min_inter_cert_time = 250000ULL; // 임의 기준
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);
  profile_entry = dot2_FindSecProfile(profile.psid);
  ASSERT_TRUE(profile_entry != nullptr);
  ASSERT_EQ(profile_entry->last_cert_sign_time, 0ULL);

  /*
   * 첫 서명 메시지 생성 시에는 서명자 식별자로 "인증서"가 선택되는 것을 확인한다.
   */
  sign_cnt = 1;
  now = 1000000ULL;
  last_cert_sign_time = now;
  signer_id_type = dot2_SelectSignerIdType(now, profile_entry);
  ASSERT_EQ(signer_id_type, kDot2SignerId_Certificate);
  ASSERT_EQ(profile_entry->last_cert_sign_time, last_cert_sign_time);

  /*
   * 최초 서명 후, 5번째 서명시마다(450msec 주기 이상 지연시마다) 서명자 식별자로 "인증서"가 반환되고
   * 그 외에는 "다이제스트"가 반환되는 것을 확인한다.
   */
#define TEST_CNT (1000)
  for (int i = 0; i < TEST_CNT; i++) {
    now += 100000ULL; // 100msec 지연
    sign_cnt++;
    signer_id_type = dot2_SelectSignerIdType(now, profile_entry);
    if ((sign_cnt % 3) == 1) {
      ASSERT_EQ(signer_id_type, kDot2SignerId_Certificate);
      last_cert_sign_time = now;
    } else {
      ASSERT_EQ(signer_id_type, kDot2SignerId_Digest);
    }
    ASSERT_EQ(profile_entry->last_cert_sign_time, last_cert_sign_time);
  }

  Dot2_Release();
}
