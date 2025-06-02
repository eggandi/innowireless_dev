/** 
  * @file
  * @brief Dot2_ConstructECRequest() API 단위테스트
  * @date 2022-07-09 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#if defined(_FFASN1C_)
#include "ffasn1-dot2-2021.h"
#else
#endif

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief 기본동작 테스트
 */
TEST(Dot2_ConstructECRequest, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECRequestConstructParams params{};
  struct Dot2ECRequestConstructResult res{};
  memset(&params, 0, sizeof(params));
  int ret;

  uint8_t ec_req[300];

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ((size_t)Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_req, ec_req), g_tv_bluetech_ec_req_size);
  }

  /*
   * 테스트 - ECRequest가 정상적으로 생성되는 것을 확인한다.
   */
  {
    // 정상동작 확인
    params.time = g_tv_bluetech_ec_req_current_time;
    params.valid_period.start = g_tv_bluetech_ec_req_valid_start;
    params.valid_period.duration.type = g_tv_bluetech_ec_req_duration_type;
    params.valid_period.duration.duration = g_tv_bluetech_ec_req_duration;
    params.valid_region.region_num = g_tv_bluetech_ec_req_region_num;
    params.valid_region.region[0] = g_tv_bluetech_ec_req_region[0];
    params.permissions.num = g_tv_bluetech_ec_req_perms_num;
    params.permissions.psid[0] = g_tv_bluetech_ec_req_perms[0];
    params.permissions.psid[1] = g_tv_bluetech_ec_req_perms[1];
    params.permissions.psid[2] = g_tv_bluetech_ec_req_perms[2];
    res = Dot2_ConstructECRequest(&params);
    ASSERT_EQ(res.ret, (int)g_tv_bluetech_ec_req_size);
    ASSERT_TRUE(res.ec_req != nullptr);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ec_req, ec_req, 54)); // 랜덤하게 생성되는 공개키 이후로는 비교 제외 (서명 등)
    free(res.ec_req);

    // current 파라미터를 0으로 전달하면 정상적으로 생성되는 것을 확인한다.
    // current 값이 테스트실행시간으로 설정되므로, 생성된 ECRequest를 테스트벡터와 비교할 수 없다.
    params.time = 0;
    params.valid_period.start = g_tv_bluetech_ec_req_valid_start;
    Dot2Time32 current = dot2_GetCurrentTime32();
    res = Dot2_ConstructECRequest(&params);
    ASSERT_EQ(res.ret, (int)g_tv_bluetech_ec_req_size);
    ASSERT_TRUE(res.ec_req != nullptr);
#if defined(_FFASN1C_)
    ASN1Error err;
    asn1_ssize_t dec_size;
    dot2SignedEeEnrollmentCertRequest *asn1_ecr;
    dec_size = asn1_oer_decode((void **)&asn1_ecr, asn1_type_dot2SignedEeEnrollmentCertRequest, res.ec_req, res.ret, &err);
    ASSERT_EQ((size_t)dec_size, g_tv_bluetech_ec_req_size);
    ASSERT_TRUE(asn1_ecr);
    dot2SignedCertificateRequest *asn1_scr;
    dec_size = asn1_oer_decode((void **)&asn1_scr,
                               asn1_type_dot2SignedCertificateRequest,
                               asn1_ecr->content.u.signedCertificateRequest.buf,
                               asn1_ecr->content.u.signedCertificateRequest.len,
                               &err);
    ASSERT_TRUE(asn1_scr);
    ASSERT_EQ(asn1_scr->tbsRequest.content.u.eca_ee.u.eeEcaCertRequest.currentTime, current);
    asn1_free_value(asn1_type_dot2SignedCertificateRequest, asn1_scr);
    asn1_free_value(asn1_type_dot2SignedEeEnrollmentCertRequest, asn1_ecr);
#endif
    free(res.ec_req);

    // valid_start 파라미터를 0으로 전달하면 정상적으로 생성되는 것을 확인한다.
    // valid_start 값이 테스트실행시간으로 설정되므로, 생성된 ECRequest를 테스트벡터와 비교할 수 없다.
    params.time = g_tv_bluetech_ec_req_current_time;
    params.valid_period.start = 0;
    res = Dot2_ConstructECRequest(&params);
    ASSERT_EQ(res.ret, (int)g_tv_bluetech_ec_req_size);
    ASSERT_TRUE(res.ec_req != nullptr);
#if defined(_FFASN1C_)
    dec_size = asn1_oer_decode((void **)&asn1_ecr, asn1_type_dot2SignedEeEnrollmentCertRequest, res.ec_req, res.ret, &err);
    ASSERT_EQ((size_t)dec_size, g_tv_bluetech_ec_req_size);
    ASSERT_TRUE(asn1_ecr);
    dec_size = asn1_oer_decode((void **)&asn1_scr,
                               asn1_type_dot2SignedCertificateRequest,
                               asn1_ecr->content.u.signedCertificateRequest.buf,
                               asn1_ecr->content.u.signedCertificateRequest.len,
                               &err);
    ASSERT_TRUE(asn1_scr);
    ASSERT_EQ(asn1_scr->tbsRequest.content.u.eca_ee.u.eeEcaCertRequest.tbsData.validityPeriod.start, current);
    asn1_free_value(asn1_type_dot2SignedCertificateRequest, asn1_scr);
    asn1_free_value(asn1_type_dot2SignedEeEnrollmentCertRequest, asn1_ecr);
#endif
    free(res.ec_req);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(API_Dot2_ConstructECRequest, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECRequestConstructParams params{};
  struct Dot2ECRequestConstructResult res{};
  memset(&params, 0, sizeof(params));
  int ret;

  /*
   * 테스트 - params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  {
    res = Dot2_ConstructECRequest(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_TRUE(res.ec_req == nullptr);
  }

  /*
   * 테스트 - 유효하지 않은 인증서유효기간 유형 전달 시 실패하는 것을 확인한다.
   */
  {
    params.time = 581219273;
    params.valid_period.start = 581219273;
    params.valid_period.duration.type = kDot2CertDurationType_Max + 1;
    params.valid_period.duration.duration = 6;
    params.valid_region.region_num = 1;
    params.valid_region.region[0] = 410;
    params.permissions.num = 3;
    params.permissions.psid[0] = 32;
    params.permissions.psid[1] = 35;
    params.permissions.psid[2] = 135;
    res = Dot2_ConstructECRequest(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertDurationType);
    ASSERT_TRUE(res.ec_req == nullptr);
  }

  /*
   * 테스트 - 인증서유효지역개수가 유효하지 않을 경우 실패하는 것을 확인한다.
   */
  {
    params.time = 581219273;
    params.valid_period.start = 581219273;
    params.valid_period.duration.type = kDot2CertDurationType_Years;
    params.valid_period.duration.duration = 6;
    params.valid_region.region_num = kDot2IdentifiedRegionNum_Max + 1;
    params.valid_region.region[0] = 410;
    params.permissions.num = 3;
    params.permissions.psid[0] = 32;
    params.permissions.psid[1] = 35;
    params.permissions.psid[2] = 135;
    res = Dot2_ConstructECRequest(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertRegionNum);
    ASSERT_TRUE(res.ec_req == nullptr);
  }

  /*
   * 테스트 - 인증서권한개수가 유효하지 않을 경우 실패하는 것을 확인한다.
   */
  {
    params.time = 581219273;
    params.valid_period.start = 581219273;
    params.valid_period.duration.type = kDot2CertDurationType_Years;
    params.valid_period.duration.duration = 6;
    params.valid_region.region_num = 1;
    params.valid_region.region[0] = 410;
    params.permissions.num = kDot2CertPermissionNum_Max + 1;
    params.permissions.psid[0] = 32;
    params.permissions.psid[1] = 35;
    params.permissions.psid[2] = 135;
    res = Dot2_ConstructECRequest(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertPermissionNum);
    ASSERT_TRUE(res.ec_req == nullptr);
  }

  Dot2_Release();
}
