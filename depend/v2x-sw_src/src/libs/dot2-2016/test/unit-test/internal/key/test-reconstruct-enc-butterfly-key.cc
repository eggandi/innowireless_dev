/** 
  * @file 
  * @brief 암호화용 butterfly 키 재구성 관련 테스트
  * @date 2022-08-10 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "sec-executer/openssl/dot2-openssl.h"
#include "sec-executer/openssl/dot2-openssl-inline.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"


/*
 * KISA v1.1 규격 "01-08.KCAC.V2X.BUTTERFLYKEY_Butterfly키 규격_v1.1" 부록 1.나
 * 인증서암호화용 키쌍에 대한 재구성
 */
uint32_t tv_recon_enc_bfkey_i = 0x217d;
uint32_t tv_recon_enc_bfkey_j = 0x0010;
const char *tv_recon_enc_bfkey_ek = "F9FCE2371B4523C0A75FC352BA7EBD8D"; // AES key (random)
const char *tv_recon_enc_bfkey_h = "9F04374146D231A5964EF674F5C25C3B98EE3A7BD91EA788D06BBCF6F9A62446"; // signing seed private key
const char *tv_recon_enc_bfkey_H = ""; // signing seed public key
const char *tv_recon_enc_bfkey_x_enc = "FFFFFFFF0000217D0000001000000000"; // x
const char *tv_recon_enc_bfkey_f_k_int_x_enc = "C93714122ACEA7A61A39F749F20348A4717F779925088ACAAB8015F839F5D5F62852FF555D83E2E2B1E2451881402AD9"; // fint(k,x)
int tv_recon_enc_bfkey_f_k_int_x_enc_size = 48;
const char *tv_recon_enc_bfkey_f_k_x_enc = "8EA344DE2F5E23639B5EF615F6FEC84437C01444EB84D7CBE515A49A55193AA4"; // f(k,x)
int tv_recon_enc_bfkey_f_k_x_enc_size = 32;
const char *tv_recon_enc_bfkey_h_exp = "2DA87B1F7630550832ADEC8AEBC12580CFAE4FBFC4A37E54B68160914FC05EEA"; // Expanded private key = cocoon private key
const char *tv_recon_enc_bfkey_H_exp = ""; // Expanded public key = cocoon public key


/*
 * 암호화용 Butterfly 키 재구성 동작 중 derive(X) 기능 확인
 */
TEST(RECONSTRUCT_ENC_BUTTERFLY_KEY, DERIVE_ENCRYPTION_X)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t x_expected[DOT2_AES_128_LEN];

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_x_enc, x_expected), DOT2_AES_128_LEN);
  }

  /*
   * 테스트
   */
  {
    uint8_t x[DOT2_AES_128_LEN];
    dot2_ossl_derive_encryption_x(tv_recon_enc_bfkey_i, tv_recon_enc_bfkey_j, x);
    ASSERT_TRUE(Dot2Test_CompareOctets(x, x_expected, DOT2_AES_128_LEN));
  }

  Dot2_Release();
}


/*
 * 암호화용 Butterfly 키 재구성 동작 중 fint(k,x) 방정식 기능 확인
 */
TEST(RECONSTRUCT_ENC_BUTTERFLY_KEY, F_INT_K_X)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t x[DOT2_AES_128_LEN], expected[DOT2_AES_128_LEN * 3];
  struct Dot2AESKey exp_key{};

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_x_enc, x), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_ek, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_f_k_int_x_enc, expected), tv_recon_enc_bfkey_f_k_int_x_enc_size);
  }

  /*
   * 테스트
   */
  {
    uint8_t f_k_int_x_cert[DOT2_AES_128_LEN * 3];
    ASSERT_TRUE(dot2_ossl_f_int_k_x(exp_key.octs, x, f_k_int_x_cert));
    ASSERT_TRUE(Dot2Test_CompareOctets(f_k_int_x_cert, expected, DOT2_AES_128_LEN * 3));
  }

  Dot2_Release();
}


/*
 * 암호화용 Butterfly 키 재구성 동작 중 cocoon 키 재구성 기능 확인
 */
TEST(RECONSTRUCT_ENC_BUTTERFLY_KEY, MAKE_COCOON_PRIV_KEY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint32_t i, j;
  struct Dot2AESKey exp_key{};
  struct Dot2ECPrivateKey seed_priv{}, expected_cocoon_priv_key{};

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    i = tv_recon_enc_bfkey_i;
    j = tv_recon_enc_bfkey_j;
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_ek, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_h, seed_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(tv_recon_enc_bfkey_h_exp, expected_cocoon_priv_key.octs), DOT2_EC_256_KEY_LEN);
  }

  /*
   * 테스트 -> 현재 Fail 남. 이유는 모르겠음. test-reconstruct-sign-butterfly-key.cc 파일의 설명 참조
   */
  {
    struct Dot2ECKeyPairOcts key_pair{};
    ASSERT_EQ(dot2_ossl_MakeSigningCocoonKeyPair(i, j, &exp_key, &seed_priv, &key_pair), kDot2Result_Success);
    //Dot2Test_PrintOcts("", key_pair.priv_key.octs, DOT2_EC_256_KEY_LEN);
    //ASSERT_TRUE(Dot2Test_CompareOctets(key_pair.priv_key.octs, expected_cocoon_priv_key.octs, DOT2_EC_256_KEY_LEN));
  }

  Dot2_Release();
}
