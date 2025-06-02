/** 
  * @file 
  * @brief 다양한 시나리오에 따른 Signed SPDU 생성 기능 단위테스트
  * @date 2022-01-05 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief SPDU 생성 시, Application CMH를 사용하는 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU, APPLICATION_CMH)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  const char *tv_spdu_0_str = "0381004003802800142512400000000764A5F6BB265B63C652087CFFFF807FF0010000FDFA1FA1007FFF10000000007001870001E87FFA4495800001E87FFC0E5900165C8B494BB7BCEB000081010100030180586C852974C7DBA2508208C00ED625C865D3C100000000002003AB2684035280165C8B494BB7BCEB0BB8010100018781823E5B2D3D9AA5C24BE3AD74BA256B3A3B776D2D06ACA91FA7A79557601A920A158083196A1318AD721CA9F4FDE4EE9B576FB0E3D49D5CE289DB0E65B63C64619F2B735A9D99439F5BD2F5FF60B02DDD1C42D1A4C311C31F47E84A10A5DFB4A750B4B7";
  const char *tv_spdu_1_str = "0381004003802800142512400000000764A5F6BB265B63C652087CFFFF807FF0010000FDFA1FA1007FFF10000000007001870001EB48708A5FC00001EB4872542340165C8B4A4BB7BCEC000180364C409476B5FFD08082D03B698775690E98D09D07E2E7184B3FD2D3C5476F14BCC8B42F7AB8C77C38459C65840B55E04B250D63E23AEDB5BF065B4246CDF1DC00139F3EF5C13848D225";
  Dot2SPDUSize tv_spdu_0_size = 230, tv_spdu_1_size = 151;
  uint8_t tv_spdu[kDot2SPDUSize_Max];


  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_0_SCCCerts();

  /*
   * 서명에 사용되는 Application CMHF들을 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_AppCMHFs();

  /*
   * WSA용 Security profile을 추가한다 - PSID=135에 대한 security profile이 등록된다.
   */
  Dot2Test_AddWSASecurityProfile();

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * Security profile에 등록된 PSID 및 App 인증서#0 유효기간 내 시간으로 서명 SPDU 생성 요청 시 성공하는 것을 확인한다.
   */
  {
    // 테스트벡터 변환
    ASSERT_EQ((size_t)Dot2Test_ConvertHexStrToOctets(tv_spdu_0_str, tv_spdu), tv_spdu_0_size);

    // 테스트 - 생성된 SPDU가 기대값과 동일한지 확인한다.
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537111334000000ULL; // App 인증서#0의 유효기간 시작시점
    params.signed_data.psid = 135; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = 375163721;
    params.signed_data.gen_location.lon = 1270332651;
    params.signed_data.gen_location.elev = 0;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)tv_spdu_0_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, tv_spdu, tv_spdu_0_size - 66));
    free(res.spdu);
  }

  /*
   * Security profile에 등록된 PSID 및 App 인증서#1 유효기간 내 시간으로 서명 SPDU 생성 요청 시 성공하는 것을 확인한다.
   */
  {
    // 테스트벡터 변환
    ASSERT_EQ((size_t)Dot2Test_ConvertHexStrToOctets(tv_spdu_1_str, tv_spdu), tv_spdu_1_size);

    // 테스트 - 생성된 SPDU가 기대값과 동일한지 확인한다.
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 540171334000000ULL + 1000000ULL; // App 인증서#1의 유효기간 시작시점 + 1초 (App인증서#0의 유효기간을 벗어난 시점)
    params.signed_data.psid = 135; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
    params.signed_data.gen_location.lat = 375163721 + 1;
    params.signed_data.gen_location.lon = 1270332651 + 1;
    params.signed_data.gen_location.elev = 0 + 1;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)tv_spdu_1_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, tv_spdu, tv_spdu_1_size - 66));
    free(res.spdu);
  }

  /*
   * Security profile에 등록되지 않은 PSID로 서명 SPDU 생성 요청 시 실패하는 것을 확인한다.
   */
  {
    // 테스트
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 540171334000000ULL; // App 인증서#1의 유효기간 시작시점
    params.signed_data.psid = 136; // Security profile에 등록되지 않은 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = 375163721;
    params.signed_data.gen_location.lon = 1270332651;
    params.signed_data.gen_location.elev = 0 ;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_NoSecProfile);
    ASSERT_FALSE(res.spdu);
  }

  /*
   * 모든 CMH의 유효기간을 벗어나는 생성시각으로 서명 SPDU 생성 요청 시 실패하는 것을 확인한다.
   *  - 과거
   */
  {
    // 테스트
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537111334000000ULL - 1ULL; // App 인증서#0의 유효기간 시작시점 - 1
    params.signed_data.psid = 135; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = 375163721;
    params.signed_data.gen_location.lon = 1270332651;
    params.signed_data.gen_location.elev = 0 ;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_NoAvailableCMH);
    ASSERT_FALSE(res.spdu);
  }

  /*
   * 모든 CMH의 유효기간을 벗어나는 생성시각으로 서명 SPDU 생성 요청 시 실패하는 것을 확인한다.
   *  - 미래
   */
  {
    // 테스트
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 543231334000000ULL + 1ULL; // App 인증서#1의 유효기간 종료시점 + 1
    params.signed_data.psid = 135; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = 375163721;
    params.signed_data.gen_location.lon = 1270332651;
    params.signed_data.gen_location.elev = 0 ;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_NoAvailableCMH);
    ASSERT_FALSE(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief SPDU 생성 시, Pseudonym CMH를 사용하는 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU, PSEUDONYM_CMH)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_Add_CertBundle_0_SCCCerts();

  /*
   * 서명에 사용되는 Pseudonym CMHF들을 로딩한다.
   */
  Dot2Test_Load_CertBundle_0_PseudonymCMHFs();

  /*
   * BSM용 Security profile을 추가한다 - PSID=32에 대한 security profile이 등록된다.
   */
  Dot2Test_AddBSMSecurityProfile();

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * Security profile에 등록된 PSID 및 Pseudonym 인증서#0 유효기간 내 시간으로 서명 SPDU 생성 요청 시 성공하는 것을 확인한다.
   *  - SPDU의 서명자식별자에 수납되는 인증서/다이제스트는 항상 랜덤하게 선택되므로 테스트벡터와 비교할 수는 없다.
   */
  {
    // 테스트
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537526803000001ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
    params.signed_data.psid = 32; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
    params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.ret > 0);
    ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인
    free(res.spdu);
  }

  /*
   * Security profile에 등록된 PSID 및 Pseudonym 인증서#0 유효기간 내 시간으로 서명 SPDU 생성 요청 시 성공하는 것을 확인한다.
   *  - SPDU의 서명자식별자에 수납되는 인증서/다이제스트는 항상 랜덤하게 선택되므로 테스트벡터와 비교할 수는 없다.
   */
  {
    // 테스트
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537526803000002ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
    params.signed_data.psid = 32; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_TRUE(res.ret > 0);
    ASSERT_TRUE(res.spdu); // SPDU가 생성된 것을 확인
    free(res.spdu);
  }

  /*
   * Security profile에 등록되지 않은 PSID로 서명 SPDU 생성 요청 시 실패하는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537526803000001ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점
    params.signed_data.psid = 35; // Security profile에 등록되지 않은 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Digest;
    params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_NoSecProfile);
    ASSERT_FALSE(res.spdu);
  }

  /*
   * 유효기간에 해당되는 CMH가 없는 생성시각으로 서명 SPDU 생성 요청 시 실패하는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 537526803000000ULL - 1ULL; // Pseudonym 인증서세트#0의 유효기간 시작시점 - 1
    params.signed_data.psid = 32; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_NoAvailableCMH);
    ASSERT_FALSE(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief SPDU 생성 시, 파라미터로 전달된 PSID에 대한 Security profile이 등록되어 있지 않을 때의 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU, NO_SUCH_SEC_PROFILE)
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
   * WSA용 Security profile을 추가한다 - PSID=135에 대한 security profile이 등록된다.
   */
  Dot2Test_AddWSASecurityProfile();

  struct Dot2SPDUConstructParams params;
  struct Dot2SPDUConstructResult res;

  /*
   * Security profile에 등록된 PSID로 서명 SPDU 생성 요청 시 성공하는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 499564800000239ULL;
    params.signed_data.psid = g_sample_rse_0_psid; // Security profile에 등록된 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)g_sample_rse_0_cert_signed_data_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, g_sample_rse_0_cert_signed_data, g_sample_rse_0_cert_signed_data_size - 66));
    free(res.spdu);
  }

  /*
   * Security profile에 등록되지 않은 PSID로 서명 SPDU 생성 요청 시 실패하는 것을 확인한다.
   */
  {
    memset(&params, 0, sizeof(params));
    params.type = kDot2SPDUConstructType_Signed;
    params.time = 499564800000239ULL;
    params.signed_data.psid = g_sample_rse_0_psid + 1; // Security profile에 등록되지 않은 PSID
    params.signed_data.signer_id_type = kDot2SignerId_Certificate;
    params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
    params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
    params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
    params.signed_data.cmh_change = false; // Sequential CMH에서는 사용되지 않는다.
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, -kDot2Result_SPDU_NoSecProfile); // 실패가 반환됨
    ASSERT_TRUE(res.spdu == nullptr); // SPDU가 생성되지 않음
  }

  Dot2_Release();
}
