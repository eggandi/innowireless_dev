/** 
  * @file 
  * @brief 테스트에 공통으로 사용되는 Security profile 관련 공통함수 정의
  * @date 2021-12-30 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-vectors/test-vectors.h"
#include "test-common-funcs.h"


/**
 * @brief 기본(정상) Security profile을 설정한다.
 * @param[out] profile 설정할 Security profile 구조체 포인터
 */
void Dot2Test_SetSecProfile(struct Dot2SecProfile *profile)
{
  memset(profile, 0, sizeof(struct Dot2SecProfile));
  profile->psid = SEC_PROFILE_PSID;
  profile->tx.gen_time_hdr = SEC_PROFILE_TX_GEN_TIME_HDR_PRESENT;
  profile->tx.exp_time_hdr = SEC_PROFILE_TX_EXP_TIME_HDR_PRESENT;
  profile->tx.gen_location_hdr = SEC_PROFILE_TX_GEN_LOCATION_HDR_PRESENT;
  profile->tx.spdu_lifetime = SEC_PROFILE_TX_SPDU_LIFETIME;
  profile->tx.min_inter_cert_time = SEC_PROFILE_TX_MIN_INTER_CERT_TIME;
  profile->tx.sign_type = SEC_PROFILE_TX_SIGN_TYPE;
  profile->tx.ecp_format = SEC_PROFLIE_TX_ECP_FORMAT;
  profile->tx.interval = SEC_PROFILE_TX_SIGNINIG_INTERNVAL;
  profile->rx.verify_data = SEC_PROFILE_RX_VERIFY_DATA;
  profile->rx.relevance_check.replay = SEC_PROFILE_RX_RELEVANCE_CHECK_REPLAY;
  profile->rx.relevance_check.gen_time_in_past = SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_IN_PAST;
  profile->rx.relevance_check.validity_period = SEC_PROFILE_RX_RELEVANCE_CHECK_VALIDITY_PERIOD;
  profile->rx.relevance_check.gen_time_in_future = SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_IN_FUTURE;
  profile->rx.relevance_check.acceptable_future_data_period = SEC_PROFILE_RX_RELEVANCE_CHECK_ACCEPTABLE_FUTURE_DATA_PERIOD;
  profile->rx.relevance_check.gen_time_src = SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_TIME_SRC;
  profile->rx.relevance_check.exp_time = SEC_PROFILE_RX_RELEVANCE_CHECK_EXP_TIME;
  profile->rx.relevance_check.exp_time_src = SEC_PROFILE_RX_RELEVANCE_CHECK_EXP_TIME_SRC;
  profile->rx.relevance_check.gen_location_distance = SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION_DISTANCE;
  profile->rx.relevance_check.valid_distance = SEC_PROFILE_RX_RELEVANCE_CHECK_VALID_DISTANCE;
  profile->rx.relevance_check.gen_location_src = SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION_SRC;
  profile->rx.relevance_check.cert_expiry = SEC_PROFILE_RX_RELEVANCE_CHECK_CERT_EXPIRY;
  profile->rx.consistency_check.gen_location = SEC_PROFILE_RX_RELEVANCE_CHECK_GEN_LOCATION;
  profile->rx.consistency_check.overdue_crl_tolerance = SEC_PROFILE_RX_RELEVANCE_CHECK_OVERDUE_CRL_TOLERANCE;
}


/**
 * @brief WSA용 Security profile을 추가한다.
 */
void Dot2Test_AddWSASecurityProfile()
{
  struct Dot2SecProfile wsa_profile;
  memset(&wsa_profile, 0, sizeof(wsa_profile));
  wsa_profile.psid = 135;
  wsa_profile.tx.gen_time_hdr = true;
  wsa_profile.tx.exp_time_hdr = true;
  wsa_profile.tx.gen_location_hdr = true;
  wsa_profile.tx.spdu_lifetime = 30000000ULL;
  wsa_profile.tx.min_inter_cert_time = 495000ULL;
  wsa_profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  wsa_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  wsa_profile.tx.interval = 100;
  wsa_profile.rx.verify_data = true;
  wsa_profile.rx.relevance_check.replay = false;
  wsa_profile.rx.relevance_check.gen_time_in_past = false;
  wsa_profile.rx.relevance_check.gen_time_in_future = true;
  wsa_profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  wsa_profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  wsa_profile.rx.relevance_check.exp_time = true;
  wsa_profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  wsa_profile.rx.relevance_check.gen_location_distance = false;
  wsa_profile.rx.relevance_check.cert_expiry = true;
  wsa_profile.rx.consistency_check.gen_location = true;
  ASSERT_EQ(Dot2_AddSecProfile(&wsa_profile), 0);
}


/**
 * @brief BSM용 Security profile을 추가한다.
 */
void Dot2Test_AddBSMSecurityProfile()
{
  struct Dot2SecProfile bsm_profile;
  memset(&bsm_profile, 0, sizeof(bsm_profile));
  bsm_profile.psid = 32;
  bsm_profile.tx.gen_time_hdr = false;
  bsm_profile.tx.gen_location_hdr = false;
  bsm_profile.tx.exp_time_hdr = false;
  bsm_profile.tx.spdu_lifetime = 30000000ULL;
  bsm_profile.tx.min_inter_cert_time = 495000ULL;
  bsm_profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  bsm_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  bsm_profile.tx.interval = 100;
  bsm_profile.rx.verify_data = true;
  bsm_profile.rx.relevance_check.replay = true;
  bsm_profile.rx.relevance_check.gen_time_in_past = true;
  bsm_profile.rx.relevance_check.gen_time_in_future = true;
  bsm_profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  bsm_profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  bsm_profile.rx.relevance_check.exp_time = true;
  bsm_profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  bsm_profile.rx.relevance_check.gen_location_distance = true;
  bsm_profile.rx.relevance_check.valid_distance = 2000;
  bsm_profile.rx.relevance_check.gen_location_src = kDot2ConsistencyLocationSource_SecurityHeader;
  bsm_profile.rx.relevance_check.cert_expiry = true;
  bsm_profile.rx.consistency_check.gen_location = true;
  ASSERT_EQ(Dot2_AddSecProfile(&bsm_profile), 0);
}


/**
 * @brief PVD용 Security profile을 추가한다.
 */
void Dot2Test_AddPVDSecurityProfile()
{
  struct Dot2SecProfile pvd_profile;
  pvd_profile.psid = 38;
  pvd_profile.tx.gen_time_hdr = true;
  pvd_profile.tx.exp_time_hdr = true;
  pvd_profile.tx.gen_location_hdr = true;
  pvd_profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  pvd_profile.tx.min_inter_cert_time = 495000ULL;
  pvd_profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  pvd_profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  pvd_profile.tx.interval = 100;
  pvd_profile.rx.verify_data = true;
  pvd_profile.rx.relevance_check.replay = false;
  pvd_profile.rx.relevance_check.gen_time_in_past = false;
  pvd_profile.rx.relevance_check.gen_time_in_future = true;
  pvd_profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  pvd_profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  pvd_profile.rx.relevance_check.exp_time = true;
  pvd_profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  pvd_profile.rx.relevance_check.gen_location_distance = false;
  pvd_profile.rx.relevance_check.cert_expiry = true;
  pvd_profile.rx.consistency_check.gen_location = true;
  ASSERT_EQ(Dot2_AddSecProfile(&pvd_profile), 0);
}
