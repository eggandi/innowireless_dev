/** 
  * @file 
  * @brief Rotate CMHF 생성 관련 테스트
  * @date 2022-08-05 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"
#include "certificate/cert-info/dot2-cert-info.h"


/**
 * @brief 기본 동작을 확인한다.
 */
TEST(MAKE_ROTATE_CMHF, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  int ret;
  uint32_t i;
  Dot2CertJvalue j_max;
  struct Dot2AESKey exp_key;
  struct Dot2ECPrivateKey seed_priv, recon_privs[kDot2CertJvalue_Max+1], priv_keys[kDot2CertJvalue_Max+1], expected_priv_keys[kDot2CertJvalue_Max+1];
  struct Dot2Cert certs[kDot2CertJvalue_Max+1], issuer;
  uint8_t expected_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize expected_cmhf_size;

  /*
   * 테스트벡터 #0
   */
  {
    // 준비
    {
      i = 0x13a;
      j_max = 0x13;

      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, issuer.octs), (size_t)g_tv_bundle_0_pca_size);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_seed_priv_key, seed_priv.octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_expansion_key, exp_key.octs), DOT2_AES_128_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_recon_priv, recon_privs[0].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_recon_priv, recon_privs[1].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_recon_priv, recon_privs[2].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_recon_priv, recon_privs[3].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_recon_priv, recon_privs[4].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_recon_priv, recon_privs[5].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_recon_priv, recon_privs[6].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_recon_priv, recon_privs[7].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_recon_priv, recon_privs[8].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_recon_priv, recon_privs[9].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_recon_priv, recon_privs[10].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_recon_priv, recon_privs[11].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_recon_priv, recon_privs[12].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_recon_priv, recon_privs[13].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_recon_priv, recon_privs[14].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_recon_priv, recon_privs[15].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_recon_priv, recon_privs[16].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_recon_priv, recon_privs[17].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_recon_priv, recon_privs[18].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_recon_priv, recon_privs[19].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_priv_key, expected_priv_keys[0].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_priv_key, expected_priv_keys[1].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_priv_key, expected_priv_keys[2].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_priv_key, expected_priv_keys[3].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_priv_key, expected_priv_keys[4].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_priv_key, expected_priv_keys[5].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_priv_key, expected_priv_keys[6].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_priv_key, expected_priv_keys[7].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_priv_key, expected_priv_keys[8].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_priv_key, expected_priv_keys[9].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_priv_key, expected_priv_keys[10].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_priv_key, expected_priv_keys[11].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_priv_key, expected_priv_keys[12].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_priv_key, expected_priv_keys[13].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_priv_key, expected_priv_keys[14].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_priv_key, expected_priv_keys[15].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_priv_key, expected_priv_keys[16].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_priv_key, expected_priv_keys[17].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_priv_key, expected_priv_keys[18].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_priv_key, expected_priv_keys[19].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(certs[0].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_cert, certs[0].octs), g_tv_bundle_0_pseudonym_13a_0_cert_size);
      ASSERT_EQ(certs[1].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_cert, certs[1].octs), g_tv_bundle_0_pseudonym_13a_1_cert_size);
      ASSERT_EQ(certs[2].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_cert, certs[2].octs), g_tv_bundle_0_pseudonym_13a_2_cert_size);
      ASSERT_EQ(certs[3].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_cert, certs[3].octs), g_tv_bundle_0_pseudonym_13a_3_cert_size);
      ASSERT_EQ(certs[4].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_cert, certs[4].octs), g_tv_bundle_0_pseudonym_13a_4_cert_size);
      ASSERT_EQ(certs[5].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_cert, certs[5].octs), g_tv_bundle_0_pseudonym_13a_5_cert_size);
      ASSERT_EQ(certs[6].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_cert, certs[6].octs), g_tv_bundle_0_pseudonym_13a_6_cert_size);
      ASSERT_EQ(certs[7].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_cert, certs[7].octs), g_tv_bundle_0_pseudonym_13a_7_cert_size);
      ASSERT_EQ(certs[8].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_cert, certs[8].octs), g_tv_bundle_0_pseudonym_13a_8_cert_size);
      ASSERT_EQ(certs[9].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_cert, certs[9].octs), g_tv_bundle_0_pseudonym_13a_9_cert_size);
      ASSERT_EQ(certs[10].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_cert, certs[10].octs), g_tv_bundle_0_pseudonym_13a_a_cert_size);
      ASSERT_EQ(certs[11].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_cert, certs[11].octs), g_tv_bundle_0_pseudonym_13a_b_cert_size);
      ASSERT_EQ(certs[12].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_cert, certs[12].octs), g_tv_bundle_0_pseudonym_13a_c_cert_size);
      ASSERT_EQ(certs[13].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_cert, certs[13].octs), g_tv_bundle_0_pseudonym_13a_d_cert_size);
      ASSERT_EQ(certs[14].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_cert, certs[14].octs), g_tv_bundle_0_pseudonym_13a_e_cert_size);
      ASSERT_EQ(certs[15].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_cert, certs[15].octs), g_tv_bundle_0_pseudonym_13a_f_cert_size);
      ASSERT_EQ(certs[16].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_cert, certs[16].octs), g_tv_bundle_0_pseudonym_13a_10_cert_size);
      ASSERT_EQ(certs[17].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_cert, certs[17].octs), g_tv_bundle_0_pseudonym_13a_11_cert_size);
      ASSERT_EQ(certs[18].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_cert, certs[18].octs), g_tv_bundle_0_pseudonym_13a_12_cert_size);
      ASSERT_EQ(certs[19].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_cert, certs[19].octs), g_tv_bundle_0_pseudonym_13a_13_cert_size);
      ASSERT_EQ(expected_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_cmhf, expected_cmhf), g_tv_bundle_0_pseudonym_13a_cmhf_size);
    }

    // 테스트
    {
      char *cmhf_name;
      uint8_t *cmhf;
      Dot2CMHFSize cmhf_size;
      ret = dot2_MakeRotateCMHFforImplicitCert_1(kDot2CMHType_Pseudonym,
                                                 i,
                                                 j_max,
                                                 &exp_key,
                                                 &seed_priv,
                                                 certs,
                                                 recon_privs,
                                                 &issuer,
                                                 &cmhf_name,
                                                 &cmhf,
                                                 &cmhf_size,
                                                 priv_keys);
      ASSERT_EQ(ret, kDot2Result_Success);
      ASSERT_TRUE(cmhf_name != nullptr);
      ASSERT_TRUE(cmhf != nullptr);
      ASSERT_EQ(strlen(cmhf_name), strlen(g_tv_bundle_0_pseudonym_13a_cmhf_name));
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf_name, g_tv_bundle_0_pseudonym_13a_cmhf_name, strlen(cmhf_name)));
      ASSERT_EQ(cmhf_size, expected_cmhf_size);
      ASSERT_TRUE(Dot2Test_CompareOctets(cmhf, expected_cmhf, cmhf_size));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[0].octs, expected_priv_keys[0].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[1].octs, expected_priv_keys[1].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[2].octs, expected_priv_keys[2].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[3].octs, expected_priv_keys[3].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[4].octs, expected_priv_keys[4].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[5].octs, expected_priv_keys[5].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[6].octs, expected_priv_keys[6].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[7].octs, expected_priv_keys[7].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[8].octs, expected_priv_keys[8].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[9].octs, expected_priv_keys[9].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[10].octs, expected_priv_keys[10].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[11].octs, expected_priv_keys[11].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[12].octs, expected_priv_keys[12].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[13].octs, expected_priv_keys[13].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[14].octs, expected_priv_keys[14].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[15].octs, expected_priv_keys[15].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[16].octs, expected_priv_keys[16].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[17].octs, expected_priv_keys[17].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[18].octs, expected_priv_keys[18].octs, DOT2_EC_256_KEY_LEN));
      ASSERT_TRUE(Dot2Test_CompareOctets(priv_keys[19].octs, expected_priv_keys[19].octs, DOT2_EC_256_KEY_LEN));
    }
  }

  Dot2_Release();
}

