/** 
 * @file
 * @brief 서명 생성 단위테스트
 * @date 2020-05-03
 * @author gyun
 *
 * 서명생성 시 랜덤값 K가 사용되므로 서명생성 결과에 대한 테스트벡터 비교는 불가능하다.
 * 따라서, 서명검증함수를 먼저 테스트/검증한 후, 서명생성결과를 해당 검증함수로 검증함으로써 서명생성함수를 테스트한다.
 */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "sec-executer/openssl/dot2-openssl.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-vectors/test-vectors.h"
#include "../../test-common-funcs/test-common-funcs.h"


/**
 * @brief 압축형식 서명생성 테스트
 */
TEST(SIGN_GENERATE, COMPRESSED)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

#define TEST_VECTOR_NUM 5
  uint8_t tbs[TEST_VECTOR_NUM][kDot2SPDUSize_Max];
  size_t tbs_size[TEST_VECTOR_NUM];
  struct Dot2SHA256 signer_h[TEST_VECTOR_NUM];
  EC_KEY *eck_key_pair[TEST_VECTOR_NUM];
  struct Dot2Signature sign[TEST_VECTOR_NUM];

  /*
   * 준비 - 서명 파라미터를 만든다.
   */
  {
    for (int i = 0; i < TEST_VECTOR_NUM; i++) {
      tbs_size[i] = Dot2Test_GetVariableLengthRandomOcts(tbs[i], sizeof(tbs[i]));
      Dot2Test_GetFixedLengthRandomOcts(signer_h[i].octs, DOT2_SHA_256_LEN);
      eck_key_pair[i] = dot2_ossl_GenerateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
    }
  }

  /*
   * 테스트
   */
  {
    // 서명 생성이 잘 되는 것을 확인한다.
    Dot2ECPointForm form = kDot2ECPointForm_Compressed;
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[0], tbs_size[0], &signer_h[0], eck_key_pair[0], &sign[0]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[1], tbs_size[1], &signer_h[1], eck_key_pair[1], &sign[1]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[2], tbs_size[2], &signer_h[2], eck_key_pair[2], &sign[2]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[3], tbs_size[3], &signer_h[3], eck_key_pair[3], &sign[3]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[4], tbs_size[4], &signer_h[4], eck_key_pair[4], &sign[4]), kDot2Result_Success);
    // 서명 유형을 확인한다.
    ASSERT_TRUE((sign[0].R_r.u.point.form == kDot2ECPointForm_Compressed_y_0) || (sign[0].R_r.u.point.form == kDot2ECPointForm_Compressed_y_1));
    ASSERT_TRUE((sign[1].R_r.u.point.form == kDot2ECPointForm_Compressed_y_0) || (sign[1].R_r.u.point.form == kDot2ECPointForm_Compressed_y_1));
    ASSERT_TRUE((sign[2].R_r.u.point.form == kDot2ECPointForm_Compressed_y_0) || (sign[2].R_r.u.point.form == kDot2ECPointForm_Compressed_y_1));
    ASSERT_TRUE((sign[3].R_r.u.point.form == kDot2ECPointForm_Compressed_y_0) || (sign[3].R_r.u.point.form == kDot2ECPointForm_Compressed_y_1));
    ASSERT_TRUE((sign[4].R_r.u.point.form == kDot2ECPointForm_Compressed_y_0) || (sign[4].R_r.u.point.form == kDot2ECPointForm_Compressed_y_1));
  }

  /*
   * 확인 - 생성된 서명에 대한 검증이 성공하는 것을 확인한다. (사전에 검증된 검증함수를 이용하여 확인한다)
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[0], tbs_size[0], &signer_h[0], eck_key_pair[0], &sign[0]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[1], tbs_size[1], &signer_h[1], eck_key_pair[1], &sign[1]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[2], tbs_size[2], &signer_h[2], eck_key_pair[2], &sign[2]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[3], tbs_size[3], &signer_h[3], eck_key_pair[3], &sign[3]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[4], tbs_size[4], &signer_h[4], eck_key_pair[4], &sign[4]), kDot2Result_Success);
  }

  for (int i = 0; i < TEST_VECTOR_NUM; i++) {
    EC_KEY_free(eck_key_pair[i]);
  }
  Dot2_Release();
#undef TEST_VECTOR_NUM
}


/**
 * @brief 비압축형식 서명생성 테스트
 */
TEST(SIGN_GENERATE, UNCOMPRESSED)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

#define TEST_VECTOR_NUM 5
  uint8_t tbs[TEST_VECTOR_NUM][kDot2SPDUSize_Max];
  size_t tbs_size[TEST_VECTOR_NUM];
  struct Dot2SHA256 signer_h[TEST_VECTOR_NUM];
  EC_KEY *eck_key_pair[TEST_VECTOR_NUM];
  struct Dot2Signature sign[TEST_VECTOR_NUM];

  /*
   * 준비 - 서명 파라미터를 만든다.
   */
  {
    for (int i = 0; i < TEST_VECTOR_NUM; i++) {
      tbs_size[i] = Dot2Test_GetVariableLengthRandomOcts(tbs[i], sizeof(tbs[i]));
      Dot2Test_GetFixedLengthRandomOcts(signer_h[i].octs, DOT2_SHA_256_LEN);
      eck_key_pair[i] = dot2_ossl_GenerateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
    }
  }

  /*
   * 테스트
   */
  {
    // 서명 생성이 잘 되는 것을 확인한다.
    Dot2ECPointForm form = kDot2ECPointForm_Uncompressed;
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[0], tbs_size[0], &signer_h[0], eck_key_pair[0], &sign[0]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[1], tbs_size[1], &signer_h[1], eck_key_pair[1], &sign[1]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[2], tbs_size[2], &signer_h[2], eck_key_pair[2], &sign[2]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[3], tbs_size[3], &signer_h[3], eck_key_pair[3], &sign[3]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[4], tbs_size[4], &signer_h[4], eck_key_pair[4], &sign[4]), kDot2Result_Success);
    // 서명 유형을 확인한다.
    ASSERT_TRUE(sign[0].R_r.u.point.form == kDot2ECPointForm_Uncompressed);
    ASSERT_TRUE(sign[1].R_r.u.point.form == kDot2ECPointForm_Uncompressed);
    ASSERT_TRUE(sign[2].R_r.u.point.form == kDot2ECPointForm_Uncompressed);
    ASSERT_TRUE(sign[3].R_r.u.point.form == kDot2ECPointForm_Uncompressed);
    ASSERT_TRUE(sign[4].R_r.u.point.form == kDot2ECPointForm_Uncompressed);
  }

  /*
   * 확인 - 생성된 서명에 대한 검증이 성공하는 것을 확인한다. (사전에 검증된 검증함수를 이용하여 확인한다)
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[0], tbs_size[0], &signer_h[0], eck_key_pair[0], &sign[0]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[1], tbs_size[1], &signer_h[1], eck_key_pair[1], &sign[1]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[2], tbs_size[2], &signer_h[2], eck_key_pair[2], &sign[2]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[3], tbs_size[3], &signer_h[3], eck_key_pair[3], &sign[3]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[4], tbs_size[4], &signer_h[4], eck_key_pair[4], &sign[4]), kDot2Result_Success);
  }

  for (int i = 0; i < TEST_VECTOR_NUM; i++) {
    EC_KEY_free(eck_key_pair[i]);
  }
  Dot2_Release();
#undef TEST_VECTOR_NUM
}


/**
 * @brief X-only 형식 서명생성 테스트
 */
TEST(SIGN_GENERATE, X_ONLY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

#define TEST_VECTOR_NUM 5
  uint8_t tbs[TEST_VECTOR_NUM][kDot2SPDUSize_Max];
  size_t tbs_size[TEST_VECTOR_NUM];
  struct Dot2SHA256 signer_h[TEST_VECTOR_NUM];
  EC_KEY *eck_key_pair[TEST_VECTOR_NUM];
  struct Dot2Signature sign[TEST_VECTOR_NUM];

  /*
   * 준비 - 서명 파라미터를 만든다.
   */
  {
    for (int i = 0; i < TEST_VECTOR_NUM; i++) {
      tbs_size[i] = Dot2Test_GetVariableLengthRandomOcts(tbs[i], sizeof(tbs[i]));
      Dot2Test_GetFixedLengthRandomOcts(signer_h[i].octs, DOT2_SHA_256_LEN);
      eck_key_pair[i] = dot2_ossl_GenerateECKEY(g_dot2_mib.sec_executer.ossl.ecg);
    }
  }

  /*
   * 테스트
   */
  {
    // 서명 생성이 잘 되는 것을 확인한다.
    Dot2ECPointForm form = kDot2ECPointForm_X_only;
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[0], tbs_size[0], &signer_h[0], eck_key_pair[0], &sign[0]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[1], tbs_size[1], &signer_h[1], eck_key_pair[1], &sign[1]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[2], tbs_size[2], &signer_h[2], eck_key_pair[2], &sign[2]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[3], tbs_size[3], &signer_h[3], eck_key_pair[3], &sign[3]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_GenerateSignature(form, tbs[4], tbs_size[4], &signer_h[4], eck_key_pair[4], &sign[4]), kDot2Result_Success);
    // 서명 유형을 확인한다.
    ASSERT_TRUE(sign[0].R_r.u.point.form == kDot2ECPointForm_X_only);
    ASSERT_TRUE(sign[1].R_r.u.point.form == kDot2ECPointForm_X_only);
    ASSERT_TRUE(sign[2].R_r.u.point.form == kDot2ECPointForm_X_only);
    ASSERT_TRUE(sign[3].R_r.u.point.form == kDot2ECPointForm_X_only);
    ASSERT_TRUE(sign[4].R_r.u.point.form == kDot2ECPointForm_X_only);
  }

  /*
   * 확인 - 생성된 서명에 대한 검증이 성공하는 것을 확인한다. (사전에 검증된 검증함수를 이용하여 확인한다)
   */
  {
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[0], tbs_size[0], &signer_h[0], eck_key_pair[0], &sign[0]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[1], tbs_size[1], &signer_h[1], eck_key_pair[1], &sign[1]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[2], tbs_size[2], &signer_h[2], eck_key_pair[2], &sign[2]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[3], tbs_size[3], &signer_h[3], eck_key_pair[3], &sign[3]), kDot2Result_Success);
    ASSERT_EQ(dot2_ossl_VerifySignature_1(tbs[4], tbs_size[4], &signer_h[4], eck_key_pair[4], &sign[4]), kDot2Result_Success);
  }

  for (int i = 0; i < TEST_VECTOR_NUM; i++) {
    EC_KEY_free(eck_key_pair[i]);
  }
  Dot2_Release();
#undef TEST_VECTOR_NUM
}


#if 0

#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// google test 헤더 파일
#include "gtest/gtest.h"

// 테스트 회수
#define TEST_NUM 100000


/**
 * @brief Compressed 서명 생성 기능 테스트.
 *        서명 파라미터를 실시간으로 계산하는 경우.
 */
TEST(dot2_GenerateSignature, ECDSA_NIST_P256_COMPRESSED_REALTIME)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2Signature sign;
  Dot2ECType ec_type = kDot2ECType_NISTp256;
  Dot2SignatureType sign_type = kDot2SignatureType_NISTp256;
  Dot2ECPointForm form = kDot2ECPointForm_Compressed;
  uint8_t tbs[TEST_NUM];
  Dot2MsgSize tbs_size;
  uint8_t h_signer[DOT2_SHA_256_LEN];
  struct Dot2ECKeyPair key;

  for (int i = 0; i < TEST_NUM; i++)
  {
    // 샘플 데이터 및 해시를 설정한다.
    tbs_size = i % 1400;
    for (unsigned int j = 0; j < tbs_size; j++) {
      tbs[j] = (uint8_t)j;
    }
    for (unsigned int j = 0; j < sizeof(h_signer); j++) {
      h_signer[j] = (uint8_t)i;
    }

    // 키 쌍을 생성한다.
    memset(&key, 0, sizeof(key));
    ASSERT_EQ(dot2_GenerateECKeyPair(ec_type, &key), kDot2Result_Success);

    // 서명을 생성한다.
    memset(&sign, 0, sizeof(sign));
    g_dot2_mib.ossl_sec.curves.nist_p256.sign_params_list.use = false; // 사전 계산 파라미터를 사용하지 않도록 강제 설정
    ASSERT_EQ(dot2_GenerateSignature(sign_type, form, tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);
    ASSERT_EQ(sign.type, kDot2SignatureType_NISTp256);
    Dot2ECPointForm res_form = (sign.sign.nist_p256.R_r.u.point.u.xy.y[DOT2_EC_256_KEY_LEN - 1] & 1u) ?
                               kDot2ECPointForm_Compressed_y_1 : kDot2ECPointForm_Compressed_y_0;
    ASSERT_EQ(sign.sign.nist_p256.R_r.u.point.form, res_form);

    // 생성된 서명을 검증한다.
    //  - 서명검증기능은 단위테스트를 통해 검증되었으므로, 서명검증이 성공할 경우, 서명생성기능이 정상 동작하는 것이다.
    ASSERT_EQ(dot2_VerifySignature(tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);

    dot2_ClearECKeyPair(&key);
  }

  Dot2_Release();
}


/**
 * @brief Compressed 서명 생성 기능 테스트.
 *        미리 생성해 놓은 서명 파라미터를 이용할 경우.
 */
TEST(dot2_GenerateSignature, ECDSA_NIST_P256_COMPRESSED_PRECOMPUTE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2Signature sign;
  Dot2ECType ec_type = kDot2ECType_NISTp256;
  Dot2SignatureType sign_type = kDot2SignatureType_NISTp256;
  Dot2ECPointForm form = kDot2ECPointForm_Compressed;
  uint8_t tbs[TEST_NUM];
  Dot2MsgSize tbs_size;
  uint8_t h_signer[DOT2_SHA_256_LEN];
  struct Dot2ECKeyPair key;

  for (int i = 0; i < TEST_NUM; i++)
  {
    // 샘플 데이터 및 해시를 설정한다.
    tbs_size = i % 1400;
    for (unsigned int j = 0; j < tbs_size; j++) {
      tbs[j] = (uint8_t)j;
    }
    for (unsigned int j = 0; j < sizeof(h_signer); j++) {
      h_signer[j] = (uint8_t)i;
    }

    // 키 쌍을 생성한다.
    memset(&key, 0, sizeof(key));
    ASSERT_EQ(dot2_GenerateECKeyPair(ec_type, &key), kDot2Result_Success);

    // 서명을 생성한다.
    memset(&sign, 0, sizeof(sign));
    ASSERT_EQ(dot2_GenerateSignature(sign_type, form, tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);
    ASSERT_EQ(sign.type, kDot2SignatureType_NISTp256);
    Dot2ECPointForm res_form = (sign.sign.nist_p256.R_r.u.point.u.xy.y[DOT2_EC_256_KEY_LEN - 1] & 1u) ?
                               kDot2ECPointForm_Compressed_y_1 : kDot2ECPointForm_Compressed_y_0;
    ASSERT_EQ(sign.sign.nist_p256.R_r.u.point.form, res_form);

    // 생성된 서명을 검증한다.
    //  - 서명검증기능은 단위테스트를 통해 검증되었으므로, 서명검증이 성공할 경우, 서명생성기능이 정상 동작하는 것이다.
    ASSERT_EQ(dot2_VerifySignature(tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);

    dot2_ClearECKeyPair(&key);
  }

  Dot2_Release();
}


/**
 * @brief Uncompressed 서명 생성 기능 테스트.
 *        서명 파라미터를 실시간으로 계산하는 경우.
 */
TEST(dot2_GenerateSignature, ECDSA_NIST_P256_UNCOMPRESSED_REALTIME)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2Signature sign;
  Dot2ECType ec_type = kDot2ECType_NISTp256;
  Dot2SignatureType sign_type = kDot2SignatureType_NISTp256;
  Dot2ECPointForm form = kDot2ECPointForm_Uncompressed;
  uint8_t tbs[TEST_NUM];
  Dot2MsgSize tbs_size;
  uint8_t h_signer[DOT2_SHA_256_LEN];
  struct Dot2ECKeyPair key;

  for (int i = 0; i < TEST_NUM; i++)
  {
    // 샘플 데이터 및 해시를 설정한다.
    tbs_size = i % 1400;
    for (unsigned int j = 0; j < tbs_size; j++) {
      tbs[j] = (uint8_t)j;
    }
    for (unsigned int j = 0; j < sizeof(h_signer); j++) {
      h_signer[j] = (uint8_t)i;
    }

    // 키 쌍을 생성한다.
    memset(&key, 0, sizeof(key));
    ASSERT_EQ(dot2_GenerateECKeyPair(ec_type, &key), kDot2Result_Success);

    // 서명을 생성한다.
    memset(&sign, 0, sizeof(sign));
    g_dot2_mib.ossl_sec.curves.nist_p256.sign_params_list.use = false; // 사전 계산 파라미터를 사용하지 않도록 강제 설정
    ASSERT_EQ(dot2_GenerateSignature(sign_type, form, tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);
    ASSERT_EQ(sign.type, kDot2SignatureType_NISTp256);
    ASSERT_EQ(sign.sign.nist_p256.R_r.u.point.form, form);

    // 생성된 서명을 검증한다.
    //  - 서명검증기능은 단위테스트를 통해 검증되었으므로, 서명검증이 성공할 경우, 서명생성기능이 정상 동작하는 것이다.
    ASSERT_EQ(dot2_VerifySignature(tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);

    dot2_ClearECKeyPair(&key);
  }

  Dot2_Release();
}


/**
 * @brief Uncompressed 서명 생성 기능 테스트.
 *        미리 생성해 놓은 서명 파라미터를 이용할 경우.
 */
TEST(dot2_GenerateSignature, ECDSA_NIST_P256_UNCOMPRESSED_PRECOMPUTE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2Signature sign;
  Dot2ECType ec_type = kDot2ECType_NISTp256;
  Dot2SignatureType sign_type = kDot2SignatureType_NISTp256;
  Dot2ECPointForm form = kDot2ECPointForm_Uncompressed;
  uint8_t tbs[TEST_NUM];
  Dot2MsgSize tbs_size;
  uint8_t h_signer[DOT2_SHA_256_LEN];
  struct Dot2ECKeyPair key;

  for (int i = 0; i < TEST_NUM; i++)
  {
    // 샘플 데이터 및 해시를 설정한다.
    tbs_size = i % 1400;
    for (unsigned int j = 0; j < tbs_size; j++) {
      tbs[j] = (uint8_t)j;
    }
    for (unsigned int j = 0; j < sizeof(h_signer); j++) {
      h_signer[j] = (uint8_t)i;
    }

    // 키 쌍을 생성한다.
    memset(&key, 0, sizeof(key));
    ASSERT_EQ(dot2_GenerateECKeyPair(ec_type, &key), kDot2Result_Success);

    // 서명을 생성한다.
    memset(&sign, 0, sizeof(sign));
    g_dot2_mib.ossl_sec.curves.nist_p256.sign_params_list.use = true; // 사전 계산 파라미터를 사용하도록 강제 설정
    ASSERT_EQ(dot2_GenerateSignature(sign_type, form, tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);
    ASSERT_EQ(sign.type, kDot2SignatureType_NISTp256);
    ASSERT_EQ(sign.sign.nist_p256.R_r.u.point.form, form);

    // 생성된 서명을 검증한다.
    //  - 서명검증기능은 단위테스트를 통해 검증되었으므로, 서명검증이 성공할 경우, 서명생성기능이 정상 동작하는 것이다.
    ASSERT_EQ(dot2_VerifySignature(tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);

    dot2_ClearECKeyPair(&key);
  }

  Dot2_Release();
}


/**
 * @brief X-only 서명 생성 기능 테스트.
 *        서명 파라미터를 실시간으로 계산하는 경우.
 */
TEST(dot2_GenerateSignature, ECDSA_NIST_P256_X_ONLY_REALTIME)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2Signature sign;
  Dot2ECType ec_type = kDot2ECType_NISTp256;
  Dot2SignatureType sign_type = kDot2SignatureType_NISTp256;
  Dot2ECPointForm form = kDot2ECPointForm_X_only;
  uint8_t tbs[TEST_NUM];
  Dot2MsgSize tbs_size;
  uint8_t h_signer[DOT2_SHA_256_LEN];
  struct Dot2ECKeyPair key;

  for (int i = 0; i < TEST_NUM; i++)
  {
    // 샘플 데이터 및 해시를 설정한다.
    tbs_size = i % 1400;
    for (unsigned int j = 0; j < tbs_size; j++) {
      tbs[j] = (uint8_t)j;
    }
    for (unsigned int j = 0; j < sizeof(h_signer); j++) {
      h_signer[j] = (uint8_t)i;
    }

    // 키 쌍을 생성한다.
    memset(&key, 0, sizeof(key));
    ASSERT_EQ(dot2_GenerateECKeyPair(ec_type, &key), kDot2Result_Success);

    // 서명을 생성한다.
    memset(&sign, 0, sizeof(sign));
    g_dot2_mib.ossl_sec.curves.nist_p256.sign_params_list.use = false; // 사전 계산 파라미터를 사용하지 않도록 강제 설정
    ASSERT_EQ(dot2_GenerateSignature(sign_type, form, tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);
    ASSERT_EQ(sign.type, kDot2SignatureType_NISTp256);
    ASSERT_EQ(sign.sign.nist_p256.R_r.u.point.form, form);

    // 생성된 서명을 검증한다.
    //  - 서명검증기능은 단위테스트를 통해 검증되었으므로, 서명검증이 성공할 경우, 서명생성기능이 정상 동작하는 것이다.
    ASSERT_EQ(dot2_VerifySignature(tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);

    dot2_ClearECKeyPair(&key);
  }

  Dot2_Release();
}


/**
 * @brief X-only 서명 생성 기능 테스트.
 *        미리 생성해 놓은 서명 파라미터를 이용할 경우.
 */
TEST(dot2_GenerateSignature, ECDSA_NIST_P256_X_ONLY_PRECOMPUTE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2Signature sign;
  Dot2ECType ec_type = kDot2ECType_NISTp256;
  Dot2SignatureType sign_type = kDot2SignatureType_NISTp256;
  Dot2ECPointForm form = kDot2ECPointForm_X_only;
  uint8_t tbs[TEST_NUM];
  Dot2MsgSize tbs_size;
  uint8_t h_signer[DOT2_SHA_256_LEN];
  struct Dot2ECKeyPair key;

  for (int i = 0; i < TEST_NUM; i++)
  {
    // 샘플 데이터 및 해시를 설정한다.
    tbs_size = i % 1400;
    for (unsigned int j = 0; j < tbs_size; j++) {
      tbs[j] = (uint8_t)j;
    }
    for (unsigned int j = 0; j < sizeof(h_signer); j++) {
      h_signer[j] = (uint8_t)i;
    }

    // 키 쌍을 생성한다.
    memset(&key, 0, sizeof(key));
    ASSERT_EQ(dot2_GenerateECKeyPair(ec_type, &key), kDot2Result_Success);

    // 서명을 생성한다.
    memset(&sign, 0, sizeof(sign));
    g_dot2_mib.ossl_sec.curves.nist_p256.sign_params_list.use = true; // 사전 계산 파라미터를 사용하도록 강제 설정
    ASSERT_EQ(dot2_GenerateSignature(sign_type, form, tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);
    ASSERT_EQ(sign.type, kDot2SignatureType_NISTp256);
    ASSERT_EQ(sign.sign.nist_p256.R_r.u.point.form, form);

    // 생성된 서명을 검증한다.
    //  - 서명검증기능은 단위테스트를 통해 검증되었으므로, 서명검증이 성공할 경우, 서명생성기능이 정상 동작하는 것이다.
    ASSERT_EQ(dot2_VerifySignature(tbs, tbs_size, h_signer, &key, &sign), kDot2Result_Success);

    dot2_ClearECKeyPair(&key);
  }

  Dot2_Release();
}
#endif
