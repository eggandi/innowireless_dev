/** 
 * @file
 * @brief 타원곡선 좌표(공개키, 재구성값)의 Y 좌표 복구 기능 단위테스트 구현 파일
 * @date 2020-04-03
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "sec-executer/openssl/dot2-openssl.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"
#include "dot2-2016/dot2-api-params.h"


/// 테스트 벡터 개수
#define SAMPLE_TEST_VECTOR_NUM 8


/// 샘플 키 쌍
static const uint8_t g_sample_tv[SAMPLE_TEST_VECTOR_NUM][DOT2_EC_256_POINT_LEN] = {
  { // Test vector #1
    0x04,//uncompressed
    0xea, 0xd2, 0x18, 0x59, 0x01, 0x19, 0xe8, 0x87, 0x6b, 0x29, 0x14, 0x6f, 0xf8, 0x9c, 0xa6, 0x17, // X
    0x70, 0xc4, 0xed, 0xbb, 0xf9, 0x7d, 0x38, 0xce, 0x38, 0x5e, 0xd2, 0x81, 0xd8, 0xa6, 0xb2, 0x30,
    0x28, 0xaf, 0x61, 0x28, 0x1f, 0xd3, 0x5e, 0x2f, 0xa7, 0x00, 0x25, 0x23, 0xac, 0xc8, 0x5a, 0x42, // Y
    0x9c, 0xb0, 0x6e, 0xe6, 0x64, 0x83, 0x25, 0x38, 0x9f, 0x59, 0xed, 0xfc, 0xe1, 0x40, 0x51, 0x41
  },
  { // Test vector #2
    0x04,//uncompressed
    0x11, 0x9f, 0x2f, 0x04, 0x79, 0x02, 0x78, 0x2a, 0xb0, 0xc9, 0xe2, 0x7a, 0x54, 0xaf, 0xf5, 0xeb,
    0x9b, 0x96, 0x48, 0x29, 0xca, 0x99, 0xc0, 0x6b, 0x02, 0xdd, 0xba, 0x95, 0xb0, 0xa3, 0xf6, 0xd0,
    0x8f, 0x52, 0xb7, 0x26, 0x66, 0x4c, 0xac, 0x36, 0x6f, 0xc9, 0x8a, 0xc7, 0xa0, 0x12, 0xb2, 0x68,
    0x2c, 0xbd, 0x96, 0x2e, 0x5a, 0xcb, 0x54, 0x46, 0x71, 0xd4, 0x1b, 0x94, 0x45, 0x70, 0x4d, 0x1d
  },
  { // Test vector #3
    0x04,//uncompressed
    0xd9, 0xf2, 0xb7, 0x9c, 0x17, 0x28, 0x45, 0xbf, 0xdb, 0x56, 0x0b, 0xbb, 0x01, 0x44, 0x7c, 0xa5,
    0xec, 0xc0, 0x47, 0x0a, 0x09, 0x51, 0x3b, 0x61, 0x26, 0x90, 0x2c, 0x6b, 0x4f, 0x8d, 0x10, 0x51,
    0xf8, 0x15, 0xef, 0x5e, 0xc3, 0x21, 0x28, 0xd3, 0x48, 0x78, 0x34, 0x76, 0x46, 0x78, 0x70, 0x2e,
    0x64, 0xe1, 0x64, 0xff, 0x73, 0x15, 0x18, 0x5e, 0x23, 0xaf, 0xf5, 0xfa, 0xcd, 0x96, 0xd7, 0xbc
  },
  { // Test vector #4
    0x04,//uncompressed
    0x24, 0x27, 0x7c, 0x33, 0xf4, 0x50, 0x46, 0x2d, 0xcb, 0x3d, 0x48, 0x01, 0xd5, 0x7b, 0x9c, 0xed,
    0x05, 0x18, 0x8f, 0x16, 0xc2, 0x8e, 0xda, 0x87, 0x32, 0x58, 0x04, 0x8c, 0xd1, 0x60, 0x7e, 0x0d,
    0xc4, 0x78, 0x97, 0x53, 0xe2, 0xb1, 0xf6, 0x3b, 0x32, 0xff, 0x01, 0x4e, 0xc4, 0x2c, 0xd6, 0xa6,
    0x9f, 0xac, 0x81, 0xdf, 0xe6, 0xd0, 0xd6, 0xfd, 0x4a, 0xf3, 0x72, 0xae, 0x27, 0xc4, 0x6f, 0x88
  },
  { // Test vector #5
    0x04,//uncompressed
    0xa8, 0xc5, 0xfd, 0xce, 0x8b, 0x62, 0xc5, 0xad, 0xa5, 0x98, 0xf1, 0x41, 0xad, 0xb3, 0xb2, 0x6c,
    0xf2, 0x54, 0xc2, 0x80, 0xb2, 0x85, 0x7a, 0x63, 0xd2, 0xad, 0x78, 0x3a, 0x73, 0x11, 0x5f, 0x6b,
    0x80, 0x6e, 0x1a, 0xaf, 0xec, 0x4a, 0xf8, 0x0a, 0x0d, 0x78, 0x6b, 0x3d, 0xe4, 0x53, 0x75, 0xb5,
    0x17, 0xa7, 0xe5, 0xb5, 0x1f, 0xfb, 0x2c, 0x35, 0x65, 0x37, 0xc9, 0xe6, 0xef, 0x22, 0x7d, 0x4a
  },
  { // Test vector #6
    0x04,//uncompressed
    0x7b, 0x86, 0x1d, 0xcd, 0x28, 0x44, 0xa5, 0xa8, 0x36, 0x3f, 0x6b, 0x8e, 0xf8, 0xd4, 0x93, 0x64,
    0x0f, 0x55, 0x87, 0x92, 0x17, 0x18, 0x9d, 0x80, 0x32, 0x6a, 0xad, 0x94, 0x80, 0xdf, 0xc1, 0x49,
    0xc4, 0x67, 0x5b, 0x45, 0xee, 0xb3, 0x06, 0x40, 0x5f, 0x6c, 0x33, 0xc3, 0x8b, 0xc6, 0x9e, 0xb2,
    0xbd, 0xec, 0x9b, 0x75, 0xad, 0x5a, 0xf4, 0x70, 0x6a, 0xab, 0x84, 0x54, 0x3b, 0x9c, 0xc6, 0x3a
  },
  { // Test vector #7
    0x04,//uncompressed
    0x06, 0x8c, 0x8a, 0xe4, 0x6a, 0xe6, 0x08, 0x49, 0xa4, 0x6b, 0x87, 0x22, 0x5b, 0xb6, 0xec, 0x83, // X
    0x5e, 0x43, 0x5b, 0x99, 0x4f, 0x98, 0x1c, 0xe7, 0x60, 0xad, 0x6a, 0x28, 0xe3, 0xc3, 0xab, 0xd4,
    0x38, 0xef, 0xf1, 0xef, 0x2a, 0xf0, 0x01, 0x32, 0xe5, 0x0d, 0xac, 0x1c, 0xfd, 0x95, 0x68, 0x56, // Y
    0x23, 0x41, 0x63, 0x00, 0x9b, 0x2d, 0xad, 0x8a, 0x6b, 0x3d, 0x6b, 0xd7, 0x60, 0x25, 0xdc, 0xc4
  },
  { // Test vector #8 - 유효하지 않은 데이터
    0x04,//uncompressed
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // X
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Y
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
  },
};


/**
 * @brief 정상적인 압축형식 공개키에 대한 공개키 Y 좌표 복구 기능 테스트
 *
 * 압축형식 공개키 바이트열을 EC_KEY 정보로 변환하고, EC_KEY 정보에서 비압축형식 공개키 바이트열을 얻는다.
 */
TEST(PUBLIC_KEY_Y_RECOVERY, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECPublicKey pub_key, pub_key_r;
  EC_KEY *eck_pub_key;
  int ret;

  // Test Vector #1
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[0] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[0], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // Test Vector #2
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[1] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[1], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // Test Vector #3
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[2] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[2], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // Test Vector #4
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[3] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[3], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // Test Vector #5
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[4] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[4], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // Test Vector #6
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[5] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[5], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // Test Vector #7
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[6] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, g_sample_tv[6], DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  struct Dot2ECPublicKey expected;

  // 테스트용 RCA 인증서 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_key_indicator, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 ICA 인증서 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_key_indicator, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 PCA 인증서 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_key_indicator, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 PCA 인증서 암호화용 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_enc_pub_key, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert_enc_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 ECA 인증서 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_key_indicator, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 ECA 인증서 암호화용 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_enc_pub_key, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert_enc_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 RA 인증서 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_key_indicator, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  // 테스트용 RA 인증서 암호화용 공개키
  Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_enc_pub_key, pub_key.u.octs); // X 좌표 복사
  Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert_enc_pub_key_uncomp, expected.u.octs); // 테스트벡터 결과값
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.octs, expected.u.octs, DOT2_EC_256_POINT_LEN));
  EC_KEY_free(eck_pub_key);

  Dot2_Release();
}


/**
 * @brief 비정상적인 공개키에 대한 공개키 Y 좌표 복구 기능 테스트
 */
TEST(PUBLIC_KEY_Y_RECOVERY, ABNORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECPublicKey pub_key, pub_key_r;
  EC_KEY *eck_pub_key;
  int ret;

  /*
   * Test Vector #1 - 잘못된 압축형식 입력 시, 복구된 Y 좌표가 다른것을 확인한다.
   */
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0; // 잘못된 압축형식 입력
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[0] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key != nullptr);
  ASSERT_EQ(pub_key_r.u.point.form, g_sample_tv[0][0]); // 복구된 공개키결과의 형식정보는 동일
  ASSERT_TRUE(Dot2Test_CompareOctets(pub_key_r.u.point.u.xy.x, g_sample_tv[0]+1, DOT2_EC_256_KEY_LEN)); // 복구된 공개키결과의 X좌표는 동일
  ASSERT_FALSE(Dot2Test_CompareOctets(pub_key_r.u.point.u.xy.y, g_sample_tv[0]+1+DOT2_EC_256_KEY_LEN, DOT2_EC_256_KEY_LEN)); // 복구된 공개키결과의 Y좌표는 다름
  EC_KEY_free(eck_pub_key);

  /*
   * Test Vector #8 - 유효하지 않은 X 좌표입력 시 실패하는 것을 확인한다.
   */
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[7] + 1, DOT2_EC_256_KEY_LEN); // X 좌표만 복사
  eck_pub_key = dot2_ossl_MakeECKEYAndUncompressedPubKeyOctsFromCompressedPubKeyOcts(&pub_key, &pub_key_r, &ret);
  ASSERT_TRUE(eck_pub_key == nullptr);
  ASSERT_EQ(ret, -kDot2Result_OSSL_MakeECKEYfromCompressedPubKeyOcts);

  Dot2_Release();
}


#if 0
// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "dot2-internal-funcs.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


/// 테스트 벡터 개수
#define SAMPLE_TEST_VECTOR_NUM 7

/// 샘플 키 쌍
static const uint8_t g_sample_tv[SAMPLE_TEST_VECTOR_NUM][DOT2_EC_PUB_KEY_MAX_LEN] = {
  {
    0x04,//uncompressed
    0xea, 0xd2, 0x18, 0x59, 0x01, 0x19, 0xe8, 0x87, 0x6b, 0x29, 0x14, 0x6f, 0xf8, 0x9c, 0xa6, 0x17, // X
    0x70, 0xc4, 0xed, 0xbb, 0xf9, 0x7d, 0x38, 0xce, 0x38, 0x5e, 0xd2, 0x81, 0xd8, 0xa6, 0xb2, 0x30,
    0x28, 0xaf, 0x61, 0x28, 0x1f, 0xd3, 0x5e, 0x2f, 0xa7, 0x00, 0x25, 0x23, 0xac, 0xc8, 0x5a, 0x42, // Y
    0x9c, 0xb0, 0x6e, 0xe6, 0x64, 0x83, 0x25, 0x38, 0x9f, 0x59, 0xed, 0xfc, 0xe1, 0x40, 0x51, 0x41
  },
  {
    0x04,//uncompressed
    0x11, 0x9f, 0x2f, 0x04, 0x79, 0x02, 0x78, 0x2a, 0xb0, 0xc9, 0xe2, 0x7a, 0x54, 0xaf, 0xf5, 0xeb,
    0x9b, 0x96, 0x48, 0x29, 0xca, 0x99, 0xc0, 0x6b, 0x02, 0xdd, 0xba, 0x95, 0xb0, 0xa3, 0xf6, 0xd0,
    0x8f, 0x52, 0xb7, 0x26, 0x66, 0x4c, 0xac, 0x36, 0x6f, 0xc9, 0x8a, 0xc7, 0xa0, 0x12, 0xb2, 0x68,
    0x2c, 0xbd, 0x96, 0x2e, 0x5a, 0xcb, 0x54, 0x46, 0x71, 0xd4, 0x1b, 0x94, 0x45, 0x70, 0x4d, 0x1d
  },
  {
    0x04,//uncompressed
    0xd9, 0xf2, 0xb7, 0x9c, 0x17, 0x28, 0x45, 0xbf, 0xdb, 0x56, 0x0b, 0xbb, 0x01, 0x44, 0x7c, 0xa5,
    0xec, 0xc0, 0x47, 0x0a, 0x09, 0x51, 0x3b, 0x61, 0x26, 0x90, 0x2c, 0x6b, 0x4f, 0x8d, 0x10, 0x51,
    0xf8, 0x15, 0xef, 0x5e, 0xc3, 0x21, 0x28, 0xd3, 0x48, 0x78, 0x34, 0x76, 0x46, 0x78, 0x70, 0x2e,
    0x64, 0xe1, 0x64, 0xff, 0x73, 0x15, 0x18, 0x5e, 0x23, 0xaf, 0xf5, 0xfa, 0xcd, 0x96, 0xd7, 0xbc
  },
  {
    0x04,//uncompressed
    0x24, 0x27, 0x7c, 0x33, 0xf4, 0x50, 0x46, 0x2d, 0xcb, 0x3d, 0x48, 0x01, 0xd5, 0x7b, 0x9c, 0xed,
    0x05, 0x18, 0x8f, 0x16, 0xc2, 0x8e, 0xda, 0x87, 0x32, 0x58, 0x04, 0x8c, 0xd1, 0x60, 0x7e, 0x0d,
    0xc4, 0x78, 0x97, 0x53, 0xe2, 0xb1, 0xf6, 0x3b, 0x32, 0xff, 0x01, 0x4e, 0xc4, 0x2c, 0xd6, 0xa6,
    0x9f, 0xac, 0x81, 0xdf, 0xe6, 0xd0, 0xd6, 0xfd, 0x4a, 0xf3, 0x72, 0xae, 0x27, 0xc4, 0x6f, 0x88
  },
  {
    0x04,//uncompressed
    0xa8, 0xc5, 0xfd, 0xce, 0x8b, 0x62, 0xc5, 0xad, 0xa5, 0x98, 0xf1, 0x41, 0xad, 0xb3, 0xb2, 0x6c,
    0xf2, 0x54, 0xc2, 0x80, 0xb2, 0x85, 0x7a, 0x63, 0xd2, 0xad, 0x78, 0x3a, 0x73, 0x11, 0x5f, 0x6b,
    0x80, 0x6e, 0x1a, 0xaf, 0xec, 0x4a, 0xf8, 0x0a, 0x0d, 0x78, 0x6b, 0x3d, 0xe4, 0x53, 0x75, 0xb5,
    0x17, 0xa7, 0xe5, 0xb5, 0x1f, 0xfb, 0x2c, 0x35, 0x65, 0x37, 0xc9, 0xe6, 0xef, 0x22, 0x7d, 0x4a
  },
  {
    0x04,//uncompressed
    0x7b, 0x86, 0x1d, 0xcd, 0x28, 0x44, 0xa5, 0xa8, 0x36, 0x3f, 0x6b, 0x8e, 0xf8, 0xd4, 0x93, 0x64,
    0x0f, 0x55, 0x87, 0x92, 0x17, 0x18, 0x9d, 0x80, 0x32, 0x6a, 0xad, 0x94, 0x80, 0xdf, 0xc1, 0x49,
    0xc4, 0x67, 0x5b, 0x45, 0xee, 0xb3, 0x06, 0x40, 0x5f, 0x6c, 0x33, 0xc3, 0x8b, 0xc6, 0x9e, 0xb2,
    0xbd, 0xec, 0x9b, 0x75, 0xad, 0x5a, 0xf4, 0x70, 0x6a, 0xab, 0x84, 0x54, 0x3b, 0x9c, 0xc6, 0x3a
  },
  {
    0x04,//uncompressed
    0x06, 0x8c, 0x8a, 0xe4, 0x6a, 0xe6, 0x08, 0x49, 0xa4, 0x6b, 0x87, 0x22, 0x5b, 0xb6, 0xec, 0x83, // X
    0x5e, 0x43, 0x5b, 0x99, 0x4f, 0x98, 0x1c, 0xe7, 0x60, 0xad, 0x6a, 0x28, 0xe3, 0xc3, 0xab, 0xd4,
    0x38, 0xef, 0xf1, 0xef, 0x2a, 0xf0, 0x01, 0x32, 0xe5, 0x0d, 0xac, 0x1c, 0xfd, 0x95, 0x68, 0x56, // Y
    0x23, 0x41, 0x63, 0x00, 0x9b, 0x2d, 0xad, 0x8a, 0x6b, 0x3d, 0x6b, 0xd7, 0x60, 0x25, 0xdc, 0xc4
  },
};


/**
 * @brief dot2_MakeUncompressedECPublicKey() 함수를 이용한 Y 좌표 복구 테스트
 */
TEST(dot2_MakeUncompressedECPublicKey, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom"), kDot2Result_Success);

  struct Dot2ECPublicKey pub_key;
  struct Dot2ECKeyPair key;

  // Test Vector #1
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[0] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[0], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // Test Vector #2
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[1] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[1], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // Test Vector #3
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[2] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[2], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // Test Vector #4
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[3] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[3], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // Test Vector #5
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[4] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[4], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // Test Vector #6
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[5] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[5], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // Test Vector #7
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_0;
  memcpy(pub_key.u.point.u.xy.x, g_sample_tv[6] + 1, DOT2_EC_KEY_MAX_LEN); // X 좌표만 복사
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_tv[6], DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // 샘플 rca 인증서
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1; // X 좌표만 복사
  memcpy(pub_key.u.point.u.xy.x, g_sample_rca_cert_compressed_verification_key + 1, DOT2_EC_KEY_MAX_LEN);
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_rca_cert_uncompressed_verification_key, DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // 샘플 ica 인증서
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1; // X 좌표만 복사
  memcpy(pub_key.u.point.u.xy.x, g_sample_ica_cert_compressed_verification_key + 1, DOT2_EC_KEY_MAX_LEN);
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_ica_cert_uncompressed_verification_key, DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // 샘플 eca 인증서
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1; // X 좌표만 복사
  memcpy(pub_key.u.point.u.xy.x, g_sample_eca_cert_compressed_verification_key + 1, DOT2_EC_KEY_MAX_LEN);
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_eca_cert_uncompressed_verification_key, DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // 샘플 ra 인증서
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1; // X 좌표만 복사
  memcpy(pub_key.u.point.u.xy.x, g_sample_ra_cert_compressed_verification_key + 1, DOT2_EC_KEY_MAX_LEN);
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_ra_cert_uncompressed_verification_key, DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  // 샘플 pca 인증서
  pub_key.u.point.form = kDot2ECPointForm_Compressed_y_1; // X 좌표만 복사
  memcpy(pub_key.u.point.u.xy.x, g_sample_pca_cert_compressed_verification_key + 1, DOT2_EC_KEY_MAX_LEN);
  ASSERT_EQ(dot2_MakeUncompressedECPublicKey(kDot2ECType_NISTp256, &pub_key, &key), kDot2Result_Success);
  ASSERT_TRUE(Dot2Test_CompareOctets(key.pub_key.u.octs, g_sample_pca_cert_uncompressed_verification_key, DOT2_EC_PUB_KEY_MAX_LEN));
  dot2_ClearECKeyPair(&key);

  Dot2_Release();
}
#endif
