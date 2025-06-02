/** 
  * @file 
  * @brief Signer Id에 따른 Signed SPDU 생성 기능 단위테스트
  * @date 2022-01-05 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


extern uint8_t sample_cert_signed_spdu[];
extern size_t sample_cert_signed_spdu_size;
extern uint8_t sample_digest_signed_spdu[];
extern size_t sample_digest_signed_spdu_size;


/**
 * @brief 인증서 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGNER_ID, SIGN_WITH_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * 서명에 사용되는 RSE용 CMH들을 추가한다.
   */
  Dot2Test_AddRSECMHFs();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 499564800000239ULL;
    params.signed_data.psid = g_sample_rse_0_psid;
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief 다이제스트 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGNER_ID, SIGN_WITH_DIGEST)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * 서명에 사용되는 RSE용 CMH들을 추가한다.
   */
  Dot2Test_AddRSECMHFs();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * 다이제스트 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 499564800000239ULL;
    params.signed_data.psid = g_sample_rse_0_psid;
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief Self 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGNER_ID, SIGN_WITH_SELF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * 서명에 사용되는 RSE용 CMH들을 추가한다.
   */
  Dot2Test_AddRSECMHFs();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * SELF 서명 SPDU 생성이 실패하는 것을 확인한다 - 지원되지 않는다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 499564800000239ULL;
    params.signed_data.psid = g_sample_rse_0_psid;
    params.signed_data.signer_id_type = kDot2SignerId_Self;
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidSignerIdType); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu == nullptr); // SPDU가 생성되지 않은 것을 확인
  }

  Dot2_Release();
}


/**
 * @brief Profile에 따른 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGNER_ID, SIGN_WITH_PROFILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * 서명에 사용되는 RSE용 CMH들을 추가한다.
   */
  Dot2Test_AddRSECMHFs();

  /*
   * Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 135;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL; // 495msec가 지날 때마다 인증서 서명, 그 외에는 다이제스트로 서명되도록 등록한다.
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = false;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * Profile에 따른 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.signed_data.psid = g_sample_rse_0_psid;
    params.signed_data.signer_id_type = kDot2SignerId_Profile; // Profile에 따라 SignerId가 선택되도록 한다.
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    params.signed_data.cmh_change = false;

    /*
     * 첫 SPDU는 인증서 서명 SPDU인 것을 확인한다.
     */
    params.time = 499564800000239ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 100msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 100000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 200msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 200000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 300msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 300000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 400msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 400000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 500msec 이후 시점(profile.tx.min_inter_cert_time=495 이후)에서는
     * 인증서 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 500000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 100msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 600000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 강제로 Digest 서명 SPDU를 생성하도록 요청하면 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
    params.time = 499564800000239ULL + 700000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 다시 Profile에 따라 서명 SPDU를 생성하도록 요청하면
     * 직전 인증서 서명 SPDU 생성시점으로부터 300msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Profile;
    params.time = 499564800000239ULL + 800000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 500msec 이후 시점(profile.tx.min_inter_cert_time=495 이후)에서는
     * 인증서 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Profile;
    params.time = 499564800000239ULL + 1000000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 100msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 1100000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 강제로 인증서 서명 SPDU를 생성하도록 요청하면 인증서 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.time = 499564800000239ULL + 1200000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 다시 Profile에 따라 서명 SPDU를 생성하도록 요청하면,
     * 직전 인증서 서명 SPDU 생성시점으로부터 300msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     * 원래 Profile 상으로는 최초 시점으로부터 1500msec 지난 시점에 인증서 서명 SPDU가 생성되어야 하는데,
     * 1200msec 시점에 인증서로 강제 서명했기 때문에, 이로부터 495msec 이후인 1700msec 시점에 인증서로 서명되고,
     * 그 전까지는 다이제스트로 서명된다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Profile;
    params.time = 499564800000239ULL + 1500000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 400msec 이후 시점(profile.tx.min_inter_cert_time=495 이내)에서는
     * 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 1600000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 500msec 이후 시점(profile.tx.min_inter_cert_time=495 이후)에서는
     * 인증서 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 1700000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 직전 인증서 서명 SPDU 생성시점으로부터 500msec 이후 시점(profile.tx.min_inter_cert_time=495 이후)인데,
     * 강제로 Digest 서명 SPDU를 생성하도록 요청하면 Digest 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
    params.time = 499564800000239ULL + 2200000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 그리고 100msec 이후 다시 Profile 기반 서명 SPDU를 생성하면, 직전 인증서 서명 SPDU 생성시점으로부터 495msec 이상(600msec)
     * 지났으므로 인증서 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.signed_data.signer_id_type = kDot2SignerId_Profile;
    params.time = 499564800000239ULL + 2300000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 그리고 직전 인증서 서명 SPDU 생성 후 495msec가 지나기 전까지는 다이제스트 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 2700000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_digest_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_digest_signed_spdu, sample_digest_signed_spdu_size - 66));
    free(res.spdu);

    /*
     * 그리고 직전 인증서 서명 SPDU 생성 후 500msec 이후에는 인증서 서명 SPDU가 생성되는 것을 확인한다.
     */
    params.time = 499564800000239ULL + 2800000ULL;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_cert_signed_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_cert_signed_spdu, sample_cert_signed_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/* rse-0 인증서 서명 SPDU - asn1.io에서 생성
rec1value Ieee1609Dot2Data ::= {
  protocolVersion 3,
  content signedData : {
    hashId sha256,
    tbsData {
      payload {
        data {
          protocolVersion 3,
          content unsecuredData : '00142512400000000764A5F6BB265B63C652087CFFFF807FF0010000FDFA1FA1007FFF1000000000'H
        }
      },
      headerInfo {
        psid 135
      }
    },
    signer certificate : { -- 인증서로 서명
      {
        version 3,
        type implicit,
        issuer sha256AndDigest : '163F2B7BC99253F4'H,
        toBeSigned {
          id binaryId : '66DF39628256B84E'H,
          cracaId '000000'H,
          crlSeries 0,
          validityPeriod {
            start 499525388,
            duration hours : 850
          },
          region circularRegion : {
            center { latitude 374856150, longitude 1270392830 },
            radius 3000
          },
          appPermissions {
            { psid 135 }
          },
          verifyKeyIndicator reconstructionValue : compressed-y-0 : '1445354A04AD1A94821725CA0F92F2B91B476CB12CD395C1C3DD51850521813B'H
        }
      }
    },
    signature ecdsaNistP256Signature : { -- 서명은 어차피 제대로 생성할 수 없으므로 더미값을 채운다.
      rSig compressed-y-1 : 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H,
      sSig 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H
    }
  }
}
*/
uint8_t sample_cert_signed_spdu[] = {
0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x87, 0x81, 0x01, 0x01, 0x00, 0x03, 0x01, 0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53,
0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF, 0x39, 0x62, 0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00,
0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84, 0x03, 0x52, 0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7,
0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD,
0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA, 0x0F, 0x92, 0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3,
0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85, 0x05, 0x21, 0x81, 0x3B, 0x80, 0x83, 0xCC, 0xCC, 0xCC, 0xCC,
0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_cert_signed_spdu_size = sizeof(sample_cert_signed_spdu);


/* rse-0 다이제스트 서명 SPDU - asn1.io에서 생성
rec1value Ieee1609Dot2Data ::= {
  protocolVersion 3,
  content signedData : {
    hashId sha256,
    tbsData {
      payload {
        data {
          protocolVersion 3,
          content unsecuredData : '00142512400000000764A5F6BB265B63C652087CFFFF807FF0010000FDFA1FA1007FFF1000000000'H
        }
      },
      headerInfo {
        psid 135
      }
    },
    signer digest : 'B68CE89C75396849'H, -- 다이제스트로 서명
    signature ecdsaNistP256Signature : { -- 서명은 어차피 제대로 생성할 수 없으므로 더미값을 채운다.
      rSig compressed-y-1 : 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H,
      sSig 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H
    }
  }
}
*/
uint8_t sample_digest_signed_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x87, 0x80, 0xB6, 0x8C, 0xE8, 0x9C, 0x75, 0x39, 0x68, 0x49, 0x80, 0x83, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_digest_signed_spdu_size = sizeof(sample_digest_signed_spdu);
