/** 
  * @file 
  * @brief 서명 SPDU 처리 기능 단위테스트
  * @date 2022-01-06 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


extern uint8_t sample_unknown_psid_spdu[];
extern size_t sample_unknown_psid_spdu_size;
extern uint8_t sample_altered_spdu[];
extern size_t sample_altered_spdu_size;


/**
 * @brief Security profile이 등록되어 있지 않은 SPDU 수신 시의 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU, NO_SUCH_SEC_PROFILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

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
  profile.tx.sign_type = kDot2SecProfileSign_Compressed; // Compressed 형식 서명을 생성하도록 한다.
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * Security profile에 등록된 PSID로 서명된 SPDU 수신 시 정상적으로 처리하는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_min_header_signed_data; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_min_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 135, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 135U); // PSID=135
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }

  /*
   * Security profile에 등록되지 않은 PSID로 서명된 SPDU 수신 시 처리에 실패하는 것을 확인한다.
   * 등록되지 않은 PSID=136을 파라미터로 전달한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = sample_unknown_psid_spdu; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = sample_unknown_psid_spdu_size;
    struct Dot2SPDUProcessParams params = {0, 136, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 에러인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 2U);
    ASSERT_EQ(g_callbacks.entry[1].result, -kDot2Result_NoSuchSecProfileInTable);
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief 변조된 서명 SPDU 수신 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU, ALTERED_SPDU)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * PSID=136에 대한 Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 136;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * 변조된 SPDU 수신 시 처리에 실패하는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = sample_altered_spdu; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = sample_altered_spdu_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 136, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 "서명검증실패"인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_SignatureVerificationFailed);
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief Security profile에 검증이 필요하지 않은 걸로 등록되어 있을 때 SPDU 수신 동작을 확인한다.
 *
 * 변조된 서명 SPDU일지라도, 서명검증을 수행하지 않으므로 성공적으로 처리된다.
 */
TEST(PROCESS_SIGNED_SPDU, NOT_VERIFY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * PSID=136에 대한 Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 136;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = false; // SPDU 검증을 수행하지 않도록 한다.
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * security profile의 rx.verify_data=false이므로, 변조된 SPDU 수신 시에도 처리에 성공하는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = sample_altered_spdu; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = sample_altered_spdu_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 136, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 정상인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, kDot2Result_Success);
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.content_type, kDot2Content_SignedData); // SignedData
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.signer_id_type, kDot2SignerId_Certificate); // 인증서로 서명
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.ext_h_present); // ext hash 불포함
    ASSERT_EQ(g_callbacks.entry[0].parsed->spdu.signed_data.psid, 136U); // PSID=136
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_time_present); // 생성시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.expiry_time_present); // 만기시각 불포함
    ASSERT_FALSE(g_callbacks.entry[0].parsed->spdu.signed_data.gen_location_present); // 생성좌표 불포함
    ASSERT_TRUE(g_callbacks.entry[0].parsed->ssdu != nullptr); // 페이로드 비교
    ASSERT_EQ(g_callbacks.entry[0].parsed->ssdu_size, payload_size); // 페이로드 비교
    ASSERT_TRUE(Dot2Test_CompareOctets(g_callbacks.entry[0].parsed->ssdu, payload, payload_size)); // 페이로드 비교
  }


  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/**
 * @brief 서명 SPDU의 헤더 내 PSID와 파라미터로 전달되는 PSID가 다른 경우의 동작을 확인한다.
 */
TEST(PROCESS_SIGNED_SPDU, DIFFERENT_PSID)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  Dot2_RegisterProcessSPDUCallback(Dot2Test_ProcessSPDUCallback);
  Dot2Test_InitProcessSPDUCallbackList();

  /*
  * 상위인증서들(rca, ica, eca, pca, ra)을 추가한다.
  */
  Dot2Test_AddCACerts();

  /*
   * PSID=136에 대한 Security profile을 추가한다.
   */
  struct Dot2SecProfile profile;
  profile.psid = 136;
  profile.tx.gen_time_hdr = false;
  profile.tx.gen_location_hdr = false;
  profile.tx.exp_time_hdr = false;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false;
  profile.rx.relevance_check.gen_time_in_past = false;
  profile.rx.relevance_check.gen_time_in_future = false;
  profile.rx.relevance_check.exp_time = false;
  profile.rx.relevance_check.gen_location_distance = false;
  profile.rx.relevance_check.cert_expiry = false;
  profile.rx.consistency_check.gen_location = false;
  ASSERT_EQ(Dot2_AddSecProfile(&profile), kDot2Result_Success);

  /*
   * 서명 SPDU 내 PSID는 135, 파라미터로 전달되는 PSID=136일 때 처리에 실패하는 것을 확인한다.
   */
  {
    struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(nullptr, 0, nullptr);
    ASSERT_TRUE(parsed != nullptr);
    uint8_t *spdu = g_sample_min_header_signed_data; // 최소 헤더를 갖는 Ieee1609Dot2Data(SignedData)
    size_t spdu_size = g_sample_min_header_signed_data_size;
    uint8_t *payload = g_sample_signed_data_payload;
    size_t payload_size = g_sample_signed_data_payload_size;
    struct Dot2SPDUProcessParams params = {0, 136, 374063230L, 1271023340L};
    ASSERT_EQ(Dot2_ProcessSPDU(spdu, spdu_size, &params, parsed), kDot2Result_Success);

    // 콜백함수로 전달된 결과가 실패인지 확인
    WAIT_MSG_PROCESS_CALLBACK;
    ASSERT_EQ(g_callbacks.cnt, 1U);
    ASSERT_EQ(g_callbacks.entry[0].result, -kDot2Result_DifferentPSID);
  }

  Dot2_Release();
  Dot2Test_FlushProcessSPDUCallbackList();
}


/* PSID=136으로 생성된 rse-0 인증서 서명 SPDU - asn1.io에서 생성
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
        psid 136 -- psid가 136이다.
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
    signature ecdsaNistP256Signature : {
      rSig compressed-y-1 : '8ABDA25DCFDFC49BFDC5E2321AC2EDD0CEC02B612971434C6C07D054C30969BF'H,
      sSig '339E7CC9A6D279212080C9280276AC399C1B471609D353E851E4F01A9EEC6F22'H
    }
  }
}
 */
uint8_t sample_unknown_psid_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x88, 0x81, 0x01, 0x01, 0x00, 0x03, 0x01, 0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53,
  0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF, 0x39, 0x62, 0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84, 0x03, 0x52, 0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7,
  0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD,
  0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA, 0x0F, 0x92, 0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3,
  0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85, 0x05, 0x21, 0x81, 0x3B, 0x80, 0x83, 0x8A, 0xBD, 0xA2, 0x5D,
  0xCF, 0xDF, 0xC4, 0x9B, 0xFD, 0xC5, 0xE2, 0x32, 0x1A, 0xC2, 0xED, 0xD0, 0xCE, 0xC0, 0x2B, 0x61,
  0x29, 0x71, 0x43, 0x4C, 0x6C, 0x07, 0xD0, 0x54, 0xC3, 0x09, 0x69, 0xBF, 0x33, 0x9E, 0x7C, 0xC9,
  0xA6, 0xD2, 0x79, 0x21, 0x20, 0x80, 0xC9, 0x28, 0x02, 0x76, 0xAC, 0x39, 0x9C, 0x1B, 0x47, 0x16,
  0x09, 0xD3, 0x53, 0xE8, 0x51, 0xE4, 0xF0, 0x1A, 0x9E, 0xEC, 0x6F, 0x22
};
size_t sample_unknown_psid_spdu_size = sizeof(sample_unknown_psid_spdu);


/* 변조된(psid를 135에서 136으로 임의 변경) rse-0 인증서 서명 SPDU - asn1.io에서 생성
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
        psid 136 -- psid가 136이다.
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
    signature ecdsaNistP256Signature : {
      rSig compressed-y-1 : '8ABDA25DCFDFC49BFDC5E2321AC2EDD0CEC02B612971434C6C07D054C30969BF'H,
      sSig '339E7CC9A6D279212080C9280276AC399C1B471609D353E851E4F01A9EEC6F22'H
    }
  }
}
 */
uint8_t sample_altered_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x88, 0x81, 0x01, 0x01, 0x00, 0x03, 0x01, 0x80, 0x16, 0x3F, 0x2B, 0x7B, 0xC9, 0x92, 0x53,
  0xF4, 0x50, 0x82, 0x08, 0x66, 0xDF, 0x39, 0x62, 0x82, 0x56, 0xB8, 0x4E, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x1D, 0xC6, 0x27, 0x0C, 0x84, 0x03, 0x52, 0x80, 0x16, 0x57, 0xD9, 0xD6, 0x4B, 0xB8, 0xA7,
  0xFE, 0x0B, 0xB8, 0x01, 0x01, 0x00, 0x01, 0x87, 0x81, 0x82, 0x14, 0x45, 0x35, 0x4A, 0x04, 0xAD,
  0x1A, 0x94, 0x82, 0x17, 0x25, 0xCA, 0x0F, 0x92, 0xF2, 0xB9, 0x1B, 0x47, 0x6C, 0xB1, 0x2C, 0xD3,
  0x95, 0xC1, 0xC3, 0xDD, 0x51, 0x85, 0x05, 0x21, 0x81, 0x3B, 0x80, 0x83, 0x8A, 0xBD, 0xA2, 0x5D,
  0xCF, 0xDF, 0xC4, 0x9B, 0xFD, 0xC5, 0xE2, 0x32, 0x1A, 0xC2, 0xED, 0xD0, 0xCE, 0xC0, 0x2B, 0x61,
  0x29, 0x71, 0x43, 0x4C, 0x6C, 0x07, 0xD0, 0x54, 0xC3, 0x09, 0x69, 0xBF, 0x33, 0x9E, 0x7C, 0xC9,
  0xA6, 0xD2, 0x79, 0x21, 0x20, 0x80, 0xC9, 0x28, 0x02, 0x76, 0xAC, 0x39, 0x9C, 0x1B, 0x47, 0x16,
  0x09, 0xD3, 0x53, 0xE8, 0x51, 0xE4, 0xF0, 0x1A, 0x9E, 0xEC, 0x6F, 0x22
};
size_t sample_altered_spdu_size = sizeof(sample_altered_spdu);