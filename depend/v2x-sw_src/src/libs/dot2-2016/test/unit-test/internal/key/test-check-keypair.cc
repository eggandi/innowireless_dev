/** 
  * @file 
  * @brief 키쌍 유효성 확인 관련 테스트
  * @date 2022-08-01 
  * @author gyun 
  */

// 라이브러리 내부 헤더파일
#include "dot2-internal.h"
#include "sec-executer/openssl/dot2-openssl.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


static const char *g_tv_check_keypair_priv_key_0 = "207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d";
static const char *g_tv_check_keypair_pub_key_0 = "0224277c33f450462dcb3d4801d57b9ced05188f16c28eda873258048cd1607e0d"; // comp-y-0
static const char *g_tv_check_keypair_priv_key_1 = "59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf";
static const char *g_tv_check_keypair_pub_key_1 = "02a8c5fdce8b62c5ada598f141adb3b26cf254c280b2857a63d2ad783a73115f6b"; // comp-y-0

static const char *g_tv_check_keypair_priv_key_2 = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
static const char *g_tv_check_keypair_pub_key_2 = "03ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230"; // comp-y-1
static const char *g_tv_check_keypair_priv_key_3 = "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5";
static const char *g_tv_check_keypair_pub_key_3 = "03119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d0"; // comp-y-1

static const char *g_tv_check_keypair_priv_key_4 = "f5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef";
static const char *g_tv_check_keypair_pub_key_4 = "047b861dcd2844a5a8363f6b8ef8d493640f55879217189d80326aad9480dfc149c4675b45eeb306405f6c33c38bc69eb2bdec9b75ad5af4706aab84543b9cc63a"; // uncomp
static const char *g_tv_check_keypair_priv_key_5 = "1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8";
static const char *g_tv_check_keypair_pub_key_5 = "04d9f2b79c172845bfdb560bbb01447ca5ecc0470a09513b6126902c6b4f8d1051f815ef5ec32128d3487834764678702e64e164ff7315185e23aff5facd96d7bc"; // uncomp


TEST(CHECK_KEYPAIR, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2ECPrivateKey priv_key;
  struct Dot2ECPublicKey pub_key;
  EC_KEY *eck_priv_key, *eck_pub_key;

  /*
   * 테스트 벡터 #0
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_0, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_0, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #1
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_1, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_1, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #2
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_2, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_2, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #3
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_3, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_3, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #4
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_4, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_4, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #5
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_5, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_5, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #6 - g_tv_bundle_1_enrol_cert_0_*
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_pub_key, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #7 - g_tv_bundle_1_app_cert_0
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_pub_key, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_TRUE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  Dot2_Release();
}


/*
 * 유효하지 않은 키쌍을 잘 체크하는지 확인한다.
 */
TEST(CHECK_KEYPAIR, INVALID)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  struct Dot2ECPrivateKey priv_key;
  struct Dot2ECPublicKey pub_key;
  EC_KEY *eck_priv_key, *eck_pub_key;

  /*
   * 테스트 벡터 #0 개인키와 테스트벡터 #1 공개키의 쌍을 확인한다.
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_0, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_1, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_FALSE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #2 개인키와 테스트벡터 #3 공개키의 쌍을 확인한다.
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_2, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_3, pub_key.u.octs), DOT2_EC_256_COMPRESSED_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_FALSE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  /*
   * 테스트 벡터 #4 개인키와 테스트벡터 #5 공개키의 쌍을 확인한다.
   */
  {
    // 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_priv_key_4, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_check_keypair_pub_key_5, pub_key.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // EC_KEY 생성
    eck_priv_key = dot2_ossl_MakeECKEYPrivKeyFromPrivKeyOcts(&priv_key, &ret);
    ASSERT_TRUE(eck_priv_key);
    eck_pub_key = dot2_ossl_MakeECKEYfromPubKeyOcts(&pub_key, &ret);
    ASSERT_TRUE(eck_pub_key);

    // 기능 정상동작 확인
    ASSERT_FALSE(dot2_ossl_CheckECKEYKeyPair(eck_priv_key, eck_pub_key));
    EC_KEY_free(eck_priv_key);
    EC_KEY_free(eck_pub_key);
  }

  Dot2_Release();
}
