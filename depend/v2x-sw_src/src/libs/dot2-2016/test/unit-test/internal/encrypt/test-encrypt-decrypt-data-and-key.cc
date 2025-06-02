/** 
  * @file 
  * @brief 데이타 및 키 암호화/복호화 (dot2_EncryptDataAndKey()/dot2_EncryptDataAndKey()) 기능에 대한 단위테스트
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


const char *g_tv_encrypt_decrypt_data_and_key_k = "9169155B08B07674CBADF75FB46A7B0D"; // AES 키
const char *g_tv_encrypt_decrypt_data_and_key_n = "A9F593C09EAEEA8BF0C1CF6A";
const char *g_tv_encrypt_decrypt_data_and_key_v = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"; // 송신자 임시 개인키
const char *g_tv_encrypt_decrypt_data_and_key_V = "04F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729"; // 송신자 임시 공개키
const char *g_tv_encrypt_decrypt_data_and_key_p1 = "A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9"; // 수신자 정보 해시
const char *g_tv_encrypt_decrypt_data_and_key_r = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"; // 수신자 개인키
const char *g_tv_encrypt_decrypt_data_and_key_R = "048C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB111270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E"; // 수신자 공개키
const char *g_tv_encrypt_decrypt_data_and_key_plaintext = "0653B5714D1357F4995BDDACBE10873951A1EBA663718D1AF35D2F0D52C79DE49BE622C4A6D90647BA2B004C3E8AE422FD27063AFA19AD883DCCBD97D98B8B0461B5671E75F19701C24042B8D3AF79B9FF62BC448EF9440B1EA3F7E5C0F4BFEFE3E326E62D5EE4CB4B4CFFF30AD5F49A7981ABF71617245B96E522E1ADD78A";
size_t g_tv_encrypt_decrypt_data_and_key_plaintext_size = 127;


/**
 * @brief 데이터 및 키가 정상적으로 암호화되고 복호화되는 것을 확인한다.
 */
TEST(ENCRYPT_DECRYPT_DATA_AND_KEY, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int encrypted_size, decrypted_size;
  uint8_t *encrypted, *decrypted;

  struct Dot2ECPrivateKey v{}, r{};
  struct Dot2ECPublicKey V{}, R{};
  struct Dot2AESKey k{};
  struct Dot2AESNonce n{};
  struct Dot2SHA256 p1{};
  struct Dot2AESKey C{};
  struct Dot2AESAuthTag T{};
  uint8_t plaintext[kDot2SPDUSize_Max];
  Dot2SPDUSize plaintext_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_k, k.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_n, n.octs), DOT2_AES_128_NONCE_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_v, v.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_V, V.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_p1, p1.octs), DOT2_SHA_256_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_r, r.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_R, R.u.octs), DOT2_EC_256_PUB_KEY_LEN);
    ASSERT_EQ(plaintext_size = (Dot2SPDUSize)Dot2Test_ConvertHexStrToOctets(g_tv_encrypt_decrypt_data_and_key_plaintext, plaintext), g_tv_encrypt_decrypt_data_and_key_plaintext_size);
  }

  /*
   * 데이터를 암호화한다.
   */
  encrypted = dot2_EncryptDataAndKey(plaintext, plaintext_size, &k, &n, &v, &p1, &R, &C, &T, &encrypted_size);
  ASSERT_TRUE(encrypted != nullptr);
  ASSERT_EQ((size_t)encrypted_size, plaintext_size + DOT2_AES_128_TAG_LEN);

  /*
   * 데이터를 복호화한다.
   */
  decrypted = dot2_DecryptDataAndKey(encrypted, encrypted_size, &n, &C, &V, &T, &r, &p1, &decrypted_size);
  ASSERT_TRUE(decrypted != nullptr);

  /*
   * 원문과 복호화된 데이터가 동일한지 확인한다.
   */
  ASSERT_EQ((size_t)decrypted_size, plaintext_size);
  ASSERT_TRUE(0 == memcmp(decrypted, plaintext, decrypted_size));

  free(encrypted);
  free(decrypted);

  Dot2_Release();
}
