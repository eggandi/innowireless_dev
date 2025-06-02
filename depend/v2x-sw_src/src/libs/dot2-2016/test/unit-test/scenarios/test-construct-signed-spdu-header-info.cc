/** 
  * @file 
  * @brief 다양한 헤더 구성에 따른 Signed SPDU 생성 기능 단위테스트
  * @date 2022-01-05 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


extern uint8_t sample_min_header_cert_spdu[];
extern size_t sample_min_header_cert_spdu_size;
extern uint8_t sample_gen_time_header_cert_spdu[];
extern size_t sample_gen_time_header_cert_spdu_size;
extern uint8_t sample_exp_time_header_cert_spdu[];
extern size_t sample_exp_time_header_cert_spdu_size;
extern uint8_t sample_gen_location_header_cert_spdu[];
extern size_t sample_gen_location_header_cert_spdu_size;
extern uint8_t sample_max_header_cert_spdu[];
extern size_t sample_max_header_cert_spdu_size;


/**
 * @brief 최소 헤더를 갖는 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_HEADER_INFO, MIN_HEADER_INFO)
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
   * 최소 헤더(PSID only)를 갖는 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
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
    ASSERT_EQ(res.ret, (int)sample_min_header_cert_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_min_header_cert_spdu, sample_min_header_cert_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief HeaderInfo에 GenerationTime 정보를 갖는 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_HEADER_INFO, GEN_TIME)
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
  profile.tx.gen_time_hdr = true; // HeaderInfo에 genertionTime 정보 수납
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
   * HeaderInfo에 generationTime 정보를 포함한 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
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
    ASSERT_EQ(res.ret, (int)sample_gen_time_header_cert_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_gen_time_header_cert_spdu, sample_gen_time_header_cert_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief HeaderInfo에 expiryTime 정보를 갖는 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_HEADER_INFO, EXPIRY_TIME)
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
  profile.tx.exp_time_hdr = true; // HeaderInfo에 expiryime 정보 수납
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
   * HeaderInfo에 expiryTime 정보를 포함한 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   * - params.time 값에 profile.tx.spdu_lifetime 값을 더한 시간이 headerInfo의 expiryTime에 수납된다.
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
    ASSERT_EQ(res.ret, (int)sample_exp_time_header_cert_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_exp_time_header_cert_spdu, sample_exp_time_header_cert_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief HeaderInfo에 generationLocation 정보를 갖는 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_HEADER_INFO, GEN_LOCATION)
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
  profile.tx.gen_location_hdr = true; // HeaderInfo에 generationLocation 정보 수납
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
   * HeaderInfo에 expiryTime 정보를 포함한 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
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
    ASSERT_EQ(res.ret, (int)sample_gen_location_header_cert_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_gen_location_header_cert_spdu, sample_gen_location_header_cert_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief HeaderInfo에 (현재 지원되는) 모든 정보가 포함된 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_HEADER_INFO, MAX_HEADER_INFO)
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
  profile.tx.gen_time_hdr = true; // HeaderInfo에 generationTime 정보 수납
  profile.tx.gen_location_hdr = true; // HeaderInfo에 generationLocation 정보 수납
  profile.tx.exp_time_hdr = true; // HeaderInfo에 expiryTime 정보 수납
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
   * HeaderInfo에 expiryTime 정보를 포함한 인증서 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
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
    ASSERT_EQ(res.ret, (int)sample_max_header_cert_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_max_header_cert_spdu, sample_max_header_cert_spdu_size - 66));
    free(res.spdu);
  }

  Dot2_Release();
}


/* 최소 헤더(PSID only)를 갖는 rse-0 인증서 서명 SPDU - asn1.io에서 생성
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
      headerInfo { -- psid 만 존재
        psid 135
      }
    },
    signer certificate : {
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
uint8_t sample_min_header_cert_spdu[] = {
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
size_t sample_min_header_cert_spdu_size = sizeof(sample_min_header_cert_spdu);


/* HeaderInfo에 generationTime 정보를 포함한 rse-0 인증서 서명 SPDU - asn1.io에서 생성
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
      headerInfo { -- generationTime 존재
        psid 135,
        generationTime 499564800000239
      }
    },
    signer certificate : {
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
uint8_t sample_gen_time_header_cert_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x40,
  0x01, 0x87, 0x00, 0x01, 0xC6, 0x59, 0xFE, 0x72, 0x40, 0xEF, 0x81, 0x01, 0x01, 0x00, 0x03, 0x01,
  0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53, 0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF, 0x39, 0x62,
  0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84, 0x03, 0x52,
  0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7, 0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00, 0x01, 0x87,
  0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD, 0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA, 0x0F, 0x92,
  0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3, 0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85, 0x05, 0x21,
  0x81, 0x3B, 0x80, 0x83, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_gen_time_header_cert_spdu_size = sizeof(sample_gen_time_header_cert_spdu);


/* HeaderInfo에 expiryTime 정보를 포함한 rse-0 인증서 서명 SPDU - asn1.io에서 생성
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
      headerInfo { -- expiryTime 존재
        psid 135,
        expiryTime 499564830000239
      }
    },
    signer certificate : {
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
uint8_t sample_exp_time_header_cert_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20,
  0x01, 0x87, 0x00, 0x01, 0xC6, 0x5A, 0x00, 0x3C, 0x04, 0x6F, 0x81, 0x01, 0x01, 0x00, 0x03, 0x01,
  0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53, 0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF, 0x39, 0x62,
  0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84, 0x03, 0x52,
  0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7, 0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00, 0x01, 0x87,
  0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD, 0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA, 0x0F, 0x92,
  0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3, 0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85, 0x05, 0x21,
  0x81, 0x3B, 0x80, 0x83, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_exp_time_header_cert_spdu_size = sizeof(sample_exp_time_header_cert_spdu);


/* HeaderInfo에 generationLocation 정보를 포함한 rse-0 인증서 서명 SPDU - asn1.io에서 생성
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
      headerInfo { -- generationLocation 존재
        psid 135,
        generationLocation {
          latitude 374856150,
          longitude 1270392830,
          elevation 500
        }
      }
    },
    signer certificate : {
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
uint8_t sample_gen_location_header_cert_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10,
  0x01, 0x87, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7, 0xFE, 0x01, 0xF4, 0x81, 0x01, 0x01, 0x00,
  0x03, 0x01, 0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53, 0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF,
  0x39, 0x62, 0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84,
  0x03, 0x52, 0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7, 0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00,
  0x01, 0x87, 0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD, 0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA,
  0x0F, 0x92, 0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3, 0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85,
  0x05, 0x21, 0x81, 0x3B, 0x80, 0x83, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_gen_location_header_cert_spdu_size = sizeof(sample_gen_location_header_cert_spdu);


/* HeaderInfo에 (현재 지원되는) 모든 정보를 포함한 rse-0 인증서 서명 SPDU - asn1.io에서 생성
 * p2pcdLearningRequest, missingCrlIdentifier, encryptionKey 정보는 지원하지 않는다.
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
      headerInfo { -- generationLocation 존재
        psid 135,
        generationTime 499564800000239,
        expiryTime 499564830000239,
        generationLocation {
          latitude 374856150,
          longitude 1270392830,
          elevation 500
        }
      }
    },
    signer certificate : {
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
uint8_t sample_max_header_cert_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x70,
  0x01, 0x87, 0x00, 0x01, 0xC6, 0x59, 0xFE, 0x72, 0x40, 0xEF, 0x00, 0x01, 0xC6, 0x5A, 0x00, 0x3C,
  0x04, 0x6F, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7, 0xFE, 0x01, 0xF4, 0x81, 0x01, 0x01, 0x00,
  0x03, 0x01, 0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53, 0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF,
  0x39, 0x62, 0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84,
  0x03, 0x52, 0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7, 0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00,
  0x01, 0x87, 0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD, 0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA,
  0x0F, 0x92, 0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3, 0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85,
  0x05, 0x21, 0x81, 0x3B, 0x80, 0x83, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_max_header_cert_spdu_size = sizeof(sample_max_header_cert_spdu);
