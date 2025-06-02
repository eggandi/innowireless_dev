/** 
  * @file 
  * @brief Dot2_ConstructSPDU() API를 이용한 SignedData 생성 기능에 대한 단위테스트 파일
  * @date 2021-12-29 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 인증서 서명 SignedData SPDU를 정상적으로 생성하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_SignedData, CERT_SIGNED)
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
   * WSA용 Security profile을 추가한다.
   */
  Dot2Test_AddWSASecurityProfile();

  struct Dot2SPDUConstructParams params{};
  struct Dot2SPDUConstructResult res{};

  /*
   * rse-0 CMH를 이용한 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
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
  ASSERT_EQ(res.ret, (int)g_sample_rse_0_cert_signed_data_size); // 생성된 SPDU의 길이를 확인
  ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
  // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
  ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, g_sample_rse_0_cert_signed_data, g_sample_rse_0_cert_signed_data_size - 66));
  free(res.spdu);

  Dot2_Release();
}


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 다이제스트 서명 SignedData SPDU를 정상적으로 생성하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_SignedData, DIGEST_SIGNED)
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
   * WSA용 Security profile을 추가한다.
   */
  Dot2Test_AddWSASecurityProfile();

  struct Dot2SPDUConstructParams params{};
  struct Dot2SPDUConstructResult res{};

  /*
   * rse-0 CMH를 이용한 다이제스트 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   */
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
  ASSERT_EQ(res.ret, (int)g_sample_rse_0_digest_signed_data_size); // 생성된 SPDU의 길이를 확인
  ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
  // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
  ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, g_sample_rse_0_digest_signed_data, g_sample_rse_0_digest_signed_data_size - 66));
  free(res.spdu);

  Dot2_Release();
}


/**
 * @brief Dot2_ConstructSPDU() API 호출 시, 잘못된 파라미터를 전달하면 실패하는 것을 확인한다.
 */
TEST(Dot2_ConstructSPDU_SignedData, INVALID_PARAMETERS)
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
   * WSA용 Security profile을 추가한다.
   */
  Dot2Test_AddWSASecurityProfile();

  struct Dot2SPDUConstructParams params{};
  struct Dot2SPDUConstructResult res{};

  /*
   * 파라미터 설정
   */
  memset(&params, 0, sizeof(params));
  params.type = kDot2SPDUConstructType_Signed;
  params.time = 499564800000239ULL;
  params.signed_data.psid = g_sample_rse_0_psid;
  params.signed_data.signer_id_type = kDot2SignerId_Certificate;
  params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;
  params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;
  params.signed_data.gen_location.elev = g_sample_rse_0_valid_elev;
  params.signed_data.cmh_change = false;

  /*
   * params 파라미터가 null이면 실패하는 것을 확인한다.
   */
  res = Dot2_ConstructSPDU(nullptr, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_NullParameters); // 실패 확인

  /*
   * payload 파라미터를 null, payload_size 파라미터를 0이 아닌 값으로 전달하면 실패가 반환되는 것을 확인한다.
   * payload 파라미터가 null이면 payload_size 파라미터는 0이어야 한다.
   */
  res = Dot2_ConstructSPDU(&params, nullptr, 8);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_NullParameters); // 실패 확인

  /*
   * payload 파라미터를 null이 아닌 값, payload_size 파라미터를 0으로 전달하면 실패가 반환되는 것을 확인한다.
   * payload_size 파라미터가 0이면 payload 파라미터는 null이어야 한다.
   */
  uint8_t dummy_payload[8];
  res = Dot2_ConstructSPDU(&params, dummy_payload, 0);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPayloadSize); // 실패 확인

  /*
   * 너무 긴 페이로드 전달 시 실패하는 것을 확인한다.
   */
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, kDot2SPDUSize_MaxPayload + 1);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPayloadSize); // 실패 확인

  /*
   * 유효하지 않은 PSID 전달 시 실패하는 것을 확인한다.
   */
  params.signed_data.psid = kDot2PSID_Max + 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPSID); // 실패 확인
  params.signed_data.psid = g_sample_rse_0_psid;

  /*
   * 유효하지 않은 SignerIdType 전달 시 실패하는 것을 확인한다.
   */
  params.signed_data.signer_id_type = kDot2SignerId_Max + 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidSignerIdType); // 실패 확인
  params.signed_data.signer_id_type = kDot2SignerId_Self;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidSignerIdType); // 실패 확인
  params.signed_data.signer_id_type = kDot2SignerId_Certificate;

  /*
   * 유효하지 않은 위도 전달 시 실패하는 것을 확인한다.
   */
  params.signed_data.gen_location.lat = kDot2Latitude_Min - 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPosition); // 실패 확인
  params.signed_data.gen_location.lat = kDot2Latitude_Unavailable + 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPosition); // 실패 확인
  params.signed_data.gen_location.lat = g_sample_rse_0_valid_lat;

  /*
   * 유효하지 않은 경도 전달 시 실패하는 것을 확인한다.
   */
  params.signed_data.gen_location.lon = kDot2Longitude_Min - 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPosition); // 실패 확인
  params.signed_data.gen_location.lon = kDot2Longitude_Unavailable + 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidPosition); // 실패 확인
  params.signed_data.gen_location.lon = g_sample_rse_0_valid_lon;

  /*
   * 잘못된 SPDU 유형 전달 시 실패하는 것을 확인한다.
   */
  params.type = kDot2SPDUConstructType_Max + 1;
  res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
  ASSERT_EQ(res.ret, -kDot2Result_SPDU_InvalidSPDUConstructType); // 실패 확인

  Dot2_Release();
}
