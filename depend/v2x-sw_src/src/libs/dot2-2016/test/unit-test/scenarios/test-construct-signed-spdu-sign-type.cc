/** 
  * @file 
  * @brief 서명 유형에 따른 Signed SPDU 생성 기능 단위테스트
  * @date 2022-01-05 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


extern uint8_t sample_compressed_y_0_sign_spdu[];
extern size_t sample_compressed_y_0_sign_spdu_size;
extern uint8_t sample_compressed_y_1_sign_spdu[];
extern size_t sample_compressed_y_1_sign_spdu_size;
extern uint8_t sample_uncompressed_sign_spdu[];
extern size_t sample_uncompressed_sign_spdu_size;
extern uint8_t sample_x_only_sign_spdu[];
extern size_t sample_x_only_sign_spdu_size;


/**
 * @brief Compressed 형식 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGN_TYPE, COMPRESSED_SIGN)
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
  profile.tx.sign_type = kDot2SecProfileSign_Compressed; // Compressed 형식 서명을 생성하도록 한다.
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
   * Compressed 형식 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
   * 랜덤하게 생성되는 서명이 compressed-y-0, compressed-y-1 둘다 나올 확률을 높이기 위해 100번 반복한다.
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
    for (int i = 0; i < 100; i++) {
      res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
      ASSERT_EQ(res.ret, (int)sample_compressed_y_0_sign_spdu_size); // 생성된 SPDU의 길이를 확인
      ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
      // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
      ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_compressed_y_0_sign_spdu, sample_compressed_y_0_sign_spdu_size - 66));
      ASSERT_TRUE((*(res.spdu + sample_compressed_y_0_sign_spdu_size - 65) == 0x82) || // 서명이 Compressed-y-0이거나 y-1인지 확인
                  (*(res.spdu + sample_compressed_y_0_sign_spdu_size - 65) == 0x83));
      free(res.spdu);
    }
  }

  Dot2_Release();
}

// X-only, Uncompressed 서명이 담긴 SPDU 생성 기능은 지원하지 않는다.

#if 0
/**
 * @brief Uncompressed 형식 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGN_TYPE, UNCOMPRESSED_SIGN)
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
  profile.tx.sign_type = kDot2SecProfileSign_Uncompressed; // Uncompressed 형식 서명을 생성하도록 한다.
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
   * Compressed 형식 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
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
    ASSERT_EQ(res.ret, (int)sample_uncompressed_sign_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 98바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_uncompressed_sign_spdu, sample_uncompressed_sign_spdu_size - 98));
    ASSERT_EQ(*(res.spdu + sample_uncompressed_sign_spdu_size - 97), 0x84); // 서명이 Uncompressed인지 확인
    free(res.spdu);
  }

  Dot2_Release();
}


/**
 * @brief X-only 형식 서명 SPDU 생성 동작을 확인한다.
 */
TEST(CONSTRUCT_SIGNED_SPDU_SIGN_TYPE, X_ONLY_SIGN)
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
  profile.tx.sign_type = kDot2SecProfileSign_X_only; // X-only 형식 서명을 생성하도록 한다.
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
   * Compressed 형식 서명 SPDU가 정상적으로 생성되는 것을 확인한다.
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
    params.signed_data.cmh_change = false;
    res = Dot2_ConstructSPDU(&params, g_sample_signed_data_payload, g_sample_signed_data_payload_size);
    ASSERT_EQ(res.ret, (int)sample_x_only_sign_spdu_size); // 생성된 SPDU의 길이를 확인
    ASSERT_TRUE(res.spdu != nullptr); // SPDU가 생성된 것을 확인
    // 생성된 SPDU 내용을 확인 (서명은 매번 달라지므로 서명(마지막 66바이트)은 제외하고 비교한다)
    ASSERT_TRUE(Dot2Test_CompareOctets(res.spdu, sample_x_only_sign_spdu, sample_x_only_sign_spdu_size - 66));
    ASSERT_EQ(*(res.spdu + sample_x_only_sign_spdu_size - 65), 0x80); // 서명이 Uncompressed인지 확인
    free(res.spdu);
  }

  Dot2_Release();
}

#endif

/* rse-0 인증서 다이제스트로 Compressed-y-0 형식 서명한 SPDU - asn1.io에서 생성
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
    signer digest : 'B68CE89C75396849'H,
    signature ecdsaNistP256Signature : { -- 임의로 생성한 compressed-y-0 유형의 서명
      rSig compressed-y-0 : 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE'H,
      sSig 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H
    }
  }
}
*/
uint8_t sample_compressed_y_0_sign_spdu[] = {
0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x87, 0x80, 0xB6, 0x8C, 0xE8, 0x9C, 0x75, 0x39, 0x68, 0x49, 0x80, 0x82, 0xEE, 0xEE, 0xEE,
0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xCC, 0xCC, 0xCC,
0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_compressed_y_0_sign_spdu_size = sizeof(sample_compressed_y_0_sign_spdu);


/* rse-0 인증서 다이제스트로 Compressed-y-1 형식 서명한 SPDU - asn1.io에서 생성
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
    signer digest : 'B68CE89C75396849'H,
    signature ecdsaNistP256Signature : { -- 임의로 생성한 compressed-y-1 유형의 서명
      rSig compressed-y-1 : 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H,
      sSig 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H
    }
  }
}
*/
uint8_t sample_compressed_y_1_sign_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x87, 0x80, 0xB6, 0x8C, 0xE8, 0x9C, 0x75, 0x39, 0x68, 0x49, 0x80, 0x83, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_compressed_y_1_sign_spdu_size = sizeof(sample_compressed_y_1_sign_spdu);


/* rse-0 인증서 다이제스트로 Uncompressed 형식 서명한 SPDU - asn1.io에서 생성
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
    signer digest : 'B68CE89C75396849'H,
    signature ecdsaNistP256Signature : { -- 임의로 생성한 uncompressed 유형의 서명
      rSig uncompressedP256 : {
        x 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE'H,
        y 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE'H
      }
      sSig 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H
    }
  }
}
*/
uint8_t sample_uncompressed_sign_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x87, 0x80, 0xB6, 0x8C, 0xE8, 0x9C, 0x75, 0x39, 0x68, 0x49, 0x80, 0x84, 0xEE, 0xEE, 0xEE,
  0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
  0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
  0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
  0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_uncompressed_sign_spdu_size = sizeof(sample_uncompressed_sign_spdu);


/* rse-0 인증서 다이제스트로 x-only 형식 서명한 SPDU - asn1.io에서 생성
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
    signer digest : 'B68CE89C75396849'H,
    signature ecdsaNistP256Signature : { -- 임의로 생성한 x-only 유형의 서명
      rSig x-only : '79156CC72C63B386F8F500202BD7D979F222157DB6AAC00523AD2751FA4C0DF4'H,
      sSig 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'H
    }
  }
}
*/
uint8_t sample_x_only_sign_spdu[] = {
  0x03, 0x81, 0x00, 0x40, 0x03, 0x80, 0x28, 0x00, 0x14, 0x25, 0x12, 0x40, 0x00, 0x00, 0x00, 0x07,
  0x64, 0xA5, 0xF6, 0xBB, 0x26, 0x5B, 0x63, 0xC6, 0x52, 0x08, 0x7C, 0xFF, 0xFF, 0x80, 0x7F, 0xF0,
  0x01, 0x00, 0x00, 0xFD, 0xFA, 0x1F, 0xA1, 0x00, 0x7F, 0xFF, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x87, 0x80, 0xB6, 0x8C, 0xE8, 0x9C, 0x75, 0x39, 0x68, 0x49, 0x80, 0x80, 0x79, 0x15, 0x6C,
  0xC7, 0x2C, 0x63, 0xB3, 0x86, 0xF8, 0xF5, 0x00, 0x20, 0x2B, 0xD7, 0xD9, 0x79, 0xF2, 0x22, 0x15,
  0x7D, 0xB6, 0xAA, 0xC0, 0x05, 0x23, 0xAD, 0x27, 0x51, 0xFA, 0x4C, 0x0D, 0xF4, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
  0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
size_t sample_x_only_sign_spdu_size = sizeof(sample_x_only_sign_spdu);
