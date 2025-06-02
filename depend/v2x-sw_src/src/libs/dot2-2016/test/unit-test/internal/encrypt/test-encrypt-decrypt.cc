/** 
  * @file 
  * @brief 암호화 및 복호화 동작(dot2_EncryptData()/dot2_DecryptData())에 대한 단위테스트
  * @date 2022-04-28 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "encrypt/dot2-encrypt.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"
#include "dot2-2016/dot2-api-params.h"


/*
 * 테스트 벡터
 */
const char *g_tv_encrypt_decrypt_cert_r = "00030180163F2B7BC99253F450820866DF39628256B84E00000000001DC6270C840352801657D9D64BB8A7FE0BB8010100018781821445354A04AD1A94821725CA0F92F2B91B476CB12CD395C1C3DD51850521813B";
size_t g_tv_encrypt_decrypt_cert_r_len = 85;
const char *g_tv_encrypt_decrypt_cert_r_h = "95b1bd1fb59523571c61e7287f153a83f6395e9f7411d78ab68ce89c75396849";
const char *g_tv_encrypt_decrypt_priv_key_r = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
const char *g_tv_encrypt_decrypt_pub_key_R = "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141";

static uint8_t * GetRandomData(size_t *len);


/*
 * EncryptedData 암호화/복호화 동작이 정상적으로 수행되는 것을 확인한다.
 */
TEST(ENCRYPT_DECRYPT, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t *enc, *dec;
  int enc_size, dec_size;
  uint8_t *ptext, *ctext;
  size_t ptext_len, ctext_len;

  uint8_t cert_r[kDot2SPDUSize_Max];
  Dot2SPDUSize cert_r_size;
  struct Dot2SHA256 cert_r_h{};
  struct Dot2ECPrivateKey priv_key_r{};
  struct Dot2ECPublicKey pub_key_R{};
  struct Dot2ECPublicKey V{};
  struct Dot2AESKey C{};
  struct Dot2AESAuthTag T{};
  struct Dot2AESNonce nonce{};

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_cert_r_h, cert_r_h.octs), DOT2_SHA_256_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_priv_key_r, priv_key_r.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_pub_key_R, pub_key_R.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    ASSERT_EQ(cert_r_size = (Dot2SPDUSize)Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_cert_r, cert_r), g_tv_encrypt_decrypt_cert_r_len);
  }

  /*
   * dot2_EncryptData_1() 테스트: 데이터가 정상적으로 암호화되고 다시 복호화되는 것을 확인한다.
   */
#define TEST_NUM (1000)
  for (int i = 0; i < TEST_NUM; i++)
  {
    // 랜덤 데이터 생성
    ptext = GetRandomData(&ptext_len);
    ASSERT_TRUE(ptext != nullptr);
    ctext_len = ptext_len + DOT2_AES_128_TAG_LEN;

    // 데이터가 정상적으로 암호화 되는 것을 확인한다.
    enc = dot2_EncryptData_1(ptext, ptext_len, cert_r, cert_r_size, &pub_key_R, &V, &C, &T, &nonce, &enc_size);
    ASSERT_TRUE((ctext = enc) != nullptr);
    ASSERT_EQ(enc_size, (int)ctext_len);

    // 암호화된 데이터가 정상적으로 복호화 되는 것을 확인한다.
    // 원래 데이터와 복호화된 데이터가 동일한 것을 확인한다.
    dec = dot2_DecryptData_1(ctext, ctext_len, cert_r, cert_r_size, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
    ASSERT_TRUE(dec != nullptr);
    ASSERT_EQ(dec_size, (int)ptext_len);
    ASSERT_TRUE(0 == memcmp(dec, ptext, dec_size));

    free(ptext);
    free(enc);
    free(dec);
  }

  /*
   * dot2_EncryptData_2() 테스트: 데이터가 정상적으로 암호화되고 다시 복호화되는 것을 확인한다.
   */
#define TEST_NUM (1000)
  for (int i = 0; i < TEST_NUM; i++)
  {
    // 랜덤 데이터 생성
    ptext = GetRandomData(&ptext_len);
    ASSERT_TRUE(ptext != nullptr);
    ctext_len = ptext_len + DOT2_AES_128_TAG_LEN;

    // 데이터가 정상적으로 암호화 되는 것을 확인한다.
    enc = dot2_EncryptData_2(ptext, ptext_len, &cert_r_h, &pub_key_R, &V, &C, &T, &nonce, &enc_size);
    ASSERT_TRUE((ctext = enc) != nullptr);
    ASSERT_EQ(enc_size, (int)ctext_len);

    // 암호화된 데이터가 정상적으로 복호화 되는 것을 확인한다.
    // 원래 데이터와 복호화된 데이터가 동일한 것을 확인한다.
    dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
    ASSERT_TRUE(dec != nullptr);
    ASSERT_EQ(dec_size, (int)ptext_len);
    ASSERT_TRUE(0 == memcmp(dec, ptext, dec_size));

    free(ptext);
    free(enc);
    free(dec);
  }

  Dot2_Release();
}


/*
 * 키입력데이터로 NULL 전달 시, EncryptedData 암호화/복호화 동작이 정상적으로 수행되는 것을 확인한다.
 */
TEST(ENCRYPT_DECRYPT, NULL_KEY_INPUT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t *enc1, *dec1;
  int enc1_size, dec1_size;
  uint8_t *ptext, *ctext;
  size_t ptext_len, ctext_len;

  struct Dot2SHA256 cert_r_h{};
  struct Dot2ECPrivateKey priv_key_r{};
  struct Dot2ECPublicKey pub_key_R{};
  struct Dot2ECPublicKey V{};
  struct Dot2AESKey C{};
  struct Dot2AESAuthTag T{};
  struct Dot2AESNonce nonce{};

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_cert_r_h, cert_r_h.octs), DOT2_SHA_256_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_priv_key_r, priv_key_r.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_pub_key_R, pub_key_R.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // 랜덤 데이터 생성
    ptext = GetRandomData(&ptext_len);
    ASSERT_TRUE(ptext != nullptr);
    ctext_len = ptext_len + DOT2_AES_128_TAG_LEN;
  }

  /*
   * key_input = null 전달 시 데이터가 정상적으로 암호화되고 다시 복호화되는 것을 확인한다.
   */
  {
    // key_input = null 전달 시 데이터가 정상적으로 암호화 되는 것을 확인한다.
    enc1 = dot2_EncryptData_1(ptext, ptext_len, nullptr, 0, &pub_key_R, &V, &C, &T, &nonce, &enc1_size);
    ASSERT_TRUE((ctext = enc1) != nullptr);
    ASSERT_EQ(enc1_size, (int)ctext_len);

    // key_input = null 전달 시 암호화된 데이터가 정상적으로 복호화 되는 것을 확인한다.
    // 원래 데이터와 복호화된 데이터가 동일한 것을 확인한다.
    dec1 = dot2_DecryptData_1(ctext, ctext_len, nullptr, 0, &priv_key_r, &V, &C, &T, &nonce, &dec1_size);
    ASSERT_TRUE(dec1 != nullptr);
    ASSERT_EQ(dec1_size, (int)ptext_len);
    ASSERT_TRUE(0 == memcmp(dec1, ptext, dec1_size));
  }

  free(ptext);
  free(enc1);
  free(dec1);

  Dot2_Release();
}


/*
 * 유효하지 않은 수신자 공개키 사용 시, 암호화에 실패하는 것을 확인한다.
 */
TEST(ENCRYPT_DECRYPT, INVALID_RECEIVER_PUBLIC_KEY)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t *enc, *dec;
  int enc_size, dec_size;
  uint8_t *ptext, *ctext;
  size_t ptext_len, ctext_len;

  struct Dot2SHA256 cert_r_h{};
  struct Dot2ECPrivateKey priv_key_r{};
  struct Dot2ECPublicKey pub_key_R{};
  struct Dot2ECPublicKey V{};
  struct Dot2AESKey C{};
  struct Dot2AESAuthTag T{};
  struct Dot2AESNonce nonce{};

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_cert_r_h, cert_r_h.octs), DOT2_SHA_256_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_priv_key_r, priv_key_r.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_pub_key_R, pub_key_R.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // 랜덤 데이터 생성
    ptext = GetRandomData(&ptext_len);
    ASSERT_TRUE(ptext != nullptr);
    ctext_len = ptext_len + DOT2_AES_128_TAG_LEN;
  }


  /*
   * 정상적인 수신자 공개키 사용시 암호화에 성공하는 것을 확인한다.
   */
  enc = dot2_EncryptData_2(ptext, ptext_len, &cert_r_h, &pub_key_R, &V, &C, &T, &nonce, &enc_size);
  ASSERT_TRUE((ctext = enc) != nullptr);
  ASSERT_EQ(enc_size, (int)ctext_len);

  /*
   * 비정상 수신자 공개키 사용시 암호화에 실패하는 것을 확인한다.
   */
  pub_key_R.u.octs[2]++;
  dec = dot2_EncryptData_2(ptext, ptext_len, &cert_r_h, &pub_key_R, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE((ctext = dec) == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailECDH);
  pub_key_R.u.octs[2]--;

  free(ptext);
  free(dec);

  Dot2_Release();
}


/*
 * 암호화 데이터 변조 시 복호화에 실패하는 것을 확인한다.
 */
TEST(ENCRYPT_DECRYPT, ALTERED_CIPHERTEXT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t *enc, *dec;
  int enc_size, dec_size;
  uint8_t *ptext, *ctext;
  size_t ptext_len, ctext_len;
  struct Dot2SHA256 cert_r_h{};
  struct Dot2ECPrivateKey priv_key_r{};
  struct Dot2ECPublicKey pub_key_R{};
  struct Dot2ECPublicKey V{};
  struct Dot2AESKey C{};
  struct Dot2AESAuthTag T{};
  struct Dot2AESNonce nonce{};

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_cert_r_h, cert_r_h.octs), DOT2_SHA_256_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_priv_key_r, priv_key_r.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_pub_key_R, pub_key_R.u.octs), DOT2_EC_256_PUB_KEY_LEN);

    // 랜덤 데이터 생성
    ptext = GetRandomData(&ptext_len);
    ASSERT_TRUE(ptext != nullptr);
    ctext_len = ptext_len + DOT2_AES_128_TAG_LEN;
  }

  /*
   * 데이터를 암호화한다.
   */
  enc = dot2_EncryptData_2(ptext, ptext_len, &cert_r_h, &pub_key_R, &V, &C, &T, &nonce, &enc_size);
  ASSERT_TRUE((ctext = enc) != nullptr);
  ASSERT_EQ(enc_size, (int)ctext_len);

  /*
   * 변조되지 않은 데이터가 정상적으로 복호화 되는 것을 확인한다.
   */
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec != nullptr);
  ASSERT_EQ(dec_size, (int)ptext_len);
  ASSERT_TRUE(0 == memcmp(dec, ptext, dec_size));
  free(dec);

  /*
   * 암호화 데이터가 변조되면 복호화가 실패하는 것을 확인한다.
   */
  *ctext += 1;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailAESDecrypt);
  *ctext -= 1;

  /*
   * 암호화 태그가 변조되면 복호화가 실패하는 것을 확인한다.
   */
  uint8_t *tag = ctext + ptext_len;
  *tag += 1;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailAESDecrypt);
  *tag -= 1;

  /*
   * 암호화 데이터의 길이가 달라지면 복호화가 실패하는 것을 확인한다.
   */
  dec = dot2_DecryptData_2(ctext, ctext_len - 1, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailAESDecrypt);
  dec = dot2_DecryptData_2(ctext, ctext_len + 1, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailAESDecrypt);

  /*
   * 수신자인증서 정보가 다르면 복호화가 실패하는 것을 확인한다.
   */
  cert_r_h.octs[0]++;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_DifferentECIESAuthenticationTag);
  cert_r_h.octs[0]--;

  /*
   * 수신자 개인키 정보가 다르면 복호화가 실패하는 것을 확인한다.
   */
  priv_key_r.octs[1]++;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_DifferentECIESAuthenticationTag);
  priv_key_r.octs[1]--;

  /*
   * V(임시 공개키), C(암호화된 공개키), T(Authentication tag), nonce가 변조되면 복호화가 실패하는 것을 확인한다.
   */
  V.u.octs[2] += 1;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailECDH);
  V.u.octs[2] -= 1;
  C.octs[0] += 1;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_DifferentECIESAuthenticationTag);
  C.octs[0] -= 1;
  T.octs[0] += 1;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_DifferentECIESAuthenticationTag);
  T.octs[0] -= 1;
  nonce.octs[0] += 1;
  dec = dot2_DecryptData_2(ctext, ctext_len, &cert_r_h, &priv_key_r, &V, &C, &T, &nonce, &dec_size);
  ASSERT_TRUE(dec == nullptr);
  ASSERT_EQ(dec_size, -kDot2Result_FailAESDecrypt);
  nonce.octs[0] -= 1;

  free(ptext);
  free(enc);

  Dot2_Release();
}


/**
 * @brief 랜덤 데이터를 생성한다.
 * @param[in] len 생성된 랜덤 데이터의 길이가 저장될 변수 포인터
 * @return 생성된 랜덤 데이터 바이트열
 * @retval NULL: 실패
 */
static uint8_t * GetRandomData(size_t *len)
{
  srand(time(nullptr));
  *len = (rand() % 2000) + DOT2_AES_128_TAG_LEN; // 암호문용으로 생성하는 경우 뒤에 tag가 포함되므로 최소한 tag 길이보다는 길어야 한다.
  auto *data = (uint8_t *)malloc(*len);
  if (data) {
    for (size_t i = 0; i < *len; i++) {
      *(data + i) = (uint8_t)rand();
    }
  }
  return data;
}
