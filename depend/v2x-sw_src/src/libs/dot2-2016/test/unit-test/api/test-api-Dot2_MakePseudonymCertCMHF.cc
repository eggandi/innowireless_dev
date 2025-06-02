/**
 * @file
 * @brief Dot2_MakePseudonymCertCMHF() API 테스트
 * @date 2023-02-24
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_MakePseudonymCertCMHF() API 테스트
 */
TEST(Dot2_MakePseudonymCertCMHF, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymCMHFMakeParams params{};
  struct Dot2PseudonymCMHFMakeResult res{};
  uint32_t i;
  Dot2CertJvalue j_max;
  struct Dot2AESKey exp_key{};
  struct Dot2ECPrivateKey seed_priv{}, priv_keys[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD];
  struct Dot2ECPrivateKey recon_privs[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD];
  struct Dot2Cert certs[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD], issuer{};
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  memset(&params, 0, sizeof(params));

  /*
   * 준비
   */
  {
    i = 0x13a;
    j_max = kDot2CertJvalue_PseudonymMax;
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_expansion_key, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_seed_priv_key, seed_priv.octs), DOT2_EC_256_KEY_LEN);
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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_priv_key, priv_keys[0].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_priv_key, priv_keys[1].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_priv_key, priv_keys[2].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_priv_key, priv_keys[3].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_priv_key, priv_keys[4].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_priv_key, priv_keys[5].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_priv_key, priv_keys[6].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_priv_key, priv_keys[7].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_priv_key, priv_keys[8].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_priv_key, priv_keys[9].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_priv_key, priv_keys[10].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_priv_key, priv_keys[11].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_priv_key, priv_keys[12].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_priv_key, priv_keys[13].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_priv_key, priv_keys[14].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_priv_key, priv_keys[15].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_priv_key, priv_keys[16].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_priv_key, priv_keys[17].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_priv_key, priv_keys[18].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_priv_key, priv_keys[19].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(certs[0].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_cert, certs[0].octs), (size_t)g_tv_bundle_0_pseudonym_13a_0_cert_size);
    ASSERT_EQ(certs[1].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_cert, certs[1].octs), (size_t)g_tv_bundle_0_pseudonym_13a_1_cert_size);
    ASSERT_EQ(certs[2].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_cert, certs[2].octs), (size_t)g_tv_bundle_0_pseudonym_13a_2_cert_size);
    ASSERT_EQ(certs[3].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_cert, certs[3].octs), (size_t)g_tv_bundle_0_pseudonym_13a_3_cert_size);
    ASSERT_EQ(certs[4].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_cert, certs[4].octs), (size_t)g_tv_bundle_0_pseudonym_13a_4_cert_size);
    ASSERT_EQ(certs[5].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_cert, certs[5].octs), (size_t)g_tv_bundle_0_pseudonym_13a_5_cert_size);
    ASSERT_EQ(certs[6].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_cert, certs[6].octs), (size_t)g_tv_bundle_0_pseudonym_13a_6_cert_size);
    ASSERT_EQ(certs[7].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_cert, certs[7].octs), (size_t)g_tv_bundle_0_pseudonym_13a_7_cert_size);
    ASSERT_EQ(certs[8].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_cert, certs[8].octs), (size_t)g_tv_bundle_0_pseudonym_13a_8_cert_size);
    ASSERT_EQ(certs[9].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_cert, certs[9].octs), (size_t)g_tv_bundle_0_pseudonym_13a_9_cert_size);
    ASSERT_EQ(certs[10].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_cert, certs[10].octs), (size_t)g_tv_bundle_0_pseudonym_13a_a_cert_size);
    ASSERT_EQ(certs[11].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_cert, certs[11].octs), (size_t)g_tv_bundle_0_pseudonym_13a_b_cert_size);
    ASSERT_EQ(certs[12].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_cert, certs[12].octs), (size_t)g_tv_bundle_0_pseudonym_13a_c_cert_size);
    ASSERT_EQ(certs[13].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_cert, certs[13].octs), (size_t)g_tv_bundle_0_pseudonym_13a_d_cert_size);
    ASSERT_EQ(certs[14].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_cert, certs[14].octs), (size_t)g_tv_bundle_0_pseudonym_13a_e_cert_size);
    ASSERT_EQ(certs[15].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_cert, certs[15].octs), (size_t)g_tv_bundle_0_pseudonym_13a_f_cert_size);
    ASSERT_EQ(certs[16].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_cert, certs[16].octs), (size_t)g_tv_bundle_0_pseudonym_13a_10_cert_size);
    ASSERT_EQ(certs[17].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_cert, certs[17].octs), (size_t)g_tv_bundle_0_pseudonym_13a_11_cert_size);
    ASSERT_EQ(certs[18].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_cert, certs[18].octs), (size_t)g_tv_bundle_0_pseudonym_13a_12_cert_size);
    ASSERT_EQ(certs[19].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_cert, certs[19].octs), (size_t)g_tv_bundle_0_pseudonym_13a_13_cert_size);
    ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, issuer.octs), (size_t)g_tv_bundle_0_pca_size);
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_cmhf, cmhf), (size_t)g_tv_bundle_0_pseudonym_13a_cmhf_size);
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 생성된 CMHF 확인
   */
  {
    // API 호출
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    res = Dot2_MakePseudonymCertCMHF(&params);

    // 결과 확인
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.cmhf_name);
    ASSERT_TRUE(res.cmhf);
    ASSERT_EQ(res.cmhf_size, (size_t)g_tv_bundle_0_pseudonym_13a_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cmhf_name, g_tv_bundle_0_pseudonym_13a_cmhf_name, strlen(g_tv_bundle_0_pseudonym_13a_cmhf_name)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cmhf, cmhf, cmhf_size));

    free(res.cmhf_name);
    free(res.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_MakePseudonymCertCMHF, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymCMHFMakeParams params{};
  struct Dot2PseudonymCMHFMakeResult res{};
  uint32_t i;
  Dot2CertJvalue j_max;
  struct Dot2AESKey exp_key{};
  struct Dot2ECPrivateKey seed_priv{}, priv_keys[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD];
  struct Dot2ECPrivateKey recon_privs[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD];
  struct Dot2Cert certs[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD], issuer{};
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  memset(&params, 0, sizeof(params));

  /*
   * 준비
   */
  {
    i = 0x13a;
    j_max = kDot2CertJvalue_PseudonymMax;
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_expansion_key, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_seed_priv_key, seed_priv.octs), DOT2_EC_256_KEY_LEN);
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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_priv_key, priv_keys[0].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_priv_key, priv_keys[1].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_priv_key, priv_keys[2].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_priv_key, priv_keys[3].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_priv_key, priv_keys[4].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_priv_key, priv_keys[5].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_priv_key, priv_keys[6].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_priv_key, priv_keys[7].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_priv_key, priv_keys[8].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_priv_key, priv_keys[9].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_priv_key, priv_keys[10].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_priv_key, priv_keys[11].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_priv_key, priv_keys[12].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_priv_key, priv_keys[13].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_priv_key, priv_keys[14].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_priv_key, priv_keys[15].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_priv_key, priv_keys[16].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_priv_key, priv_keys[17].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_priv_key, priv_keys[18].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_priv_key, priv_keys[19].octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(certs[0].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_0_cert, certs[0].octs), (size_t)g_tv_bundle_0_pseudonym_13a_0_cert_size);
    ASSERT_EQ(certs[1].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_1_cert, certs[1].octs), (size_t)g_tv_bundle_0_pseudonym_13a_1_cert_size);
    ASSERT_EQ(certs[2].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_2_cert, certs[2].octs), (size_t)g_tv_bundle_0_pseudonym_13a_2_cert_size);
    ASSERT_EQ(certs[3].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_3_cert, certs[3].octs), (size_t)g_tv_bundle_0_pseudonym_13a_3_cert_size);
    ASSERT_EQ(certs[4].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_4_cert, certs[4].octs), (size_t)g_tv_bundle_0_pseudonym_13a_4_cert_size);
    ASSERT_EQ(certs[5].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_5_cert, certs[5].octs), (size_t)g_tv_bundle_0_pseudonym_13a_5_cert_size);
    ASSERT_EQ(certs[6].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_6_cert, certs[6].octs), (size_t)g_tv_bundle_0_pseudonym_13a_6_cert_size);
    ASSERT_EQ(certs[7].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_7_cert, certs[7].octs), (size_t)g_tv_bundle_0_pseudonym_13a_7_cert_size);
    ASSERT_EQ(certs[8].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_8_cert, certs[8].octs), (size_t)g_tv_bundle_0_pseudonym_13a_8_cert_size);
    ASSERT_EQ(certs[9].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_9_cert, certs[9].octs), (size_t)g_tv_bundle_0_pseudonym_13a_9_cert_size);
    ASSERT_EQ(certs[10].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_a_cert, certs[10].octs), (size_t)g_tv_bundle_0_pseudonym_13a_a_cert_size);
    ASSERT_EQ(certs[11].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_b_cert, certs[11].octs), (size_t)g_tv_bundle_0_pseudonym_13a_b_cert_size);
    ASSERT_EQ(certs[12].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_c_cert, certs[12].octs), (size_t)g_tv_bundle_0_pseudonym_13a_c_cert_size);
    ASSERT_EQ(certs[13].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_d_cert, certs[13].octs), (size_t)g_tv_bundle_0_pseudonym_13a_d_cert_size);
    ASSERT_EQ(certs[14].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_e_cert, certs[14].octs), (size_t)g_tv_bundle_0_pseudonym_13a_e_cert_size);
    ASSERT_EQ(certs[15].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_f_cert, certs[15].octs), (size_t)g_tv_bundle_0_pseudonym_13a_f_cert_size);
    ASSERT_EQ(certs[16].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_10_cert, certs[16].octs), (size_t)g_tv_bundle_0_pseudonym_13a_10_cert_size);
    ASSERT_EQ(certs[17].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_11_cert, certs[17].octs), (size_t)g_tv_bundle_0_pseudonym_13a_11_cert_size);
    ASSERT_EQ(certs[18].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_12_cert, certs[18].octs), (size_t)g_tv_bundle_0_pseudonym_13a_12_cert_size);
    ASSERT_EQ(certs[19].size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_13_cert, certs[19].octs), (size_t)g_tv_bundle_0_pseudonym_13a_13_cert_size);
    ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, issuer.octs), (size_t)g_tv_bundle_0_pca_size);
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_cmhf, cmhf), (size_t)g_tv_bundle_0_pseudonym_13a_cmhf_size);
  }

  /*
   * 테스트 : 널 파라미터 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    res = Dot2_MakePseudonymCertCMHF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
  }

  /*
   * 테스트 : 유효하지 않은 i 값 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i + 1;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
  }

  /*
   * 테스트 : 유효하지 않은 j_max 값 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = 0;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CMHF_InvalidJMax);

    params.j_max = 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CMHF_InvalidJMax);

    params.j_max = j_max - 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CMHF_InvalidJMax);

    params.j_max = j_max + 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CMHF_InvalidJMax);
  }

  /*
   * 테스트 : 유효하지 않은 expansion key 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    memset(&params.exp_key, 0, sizeof(params.exp_key));
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
  }

  /*
   * 테스트 : 유효하지 않은 seed_priv 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    memset(&params.seed_priv, 0, sizeof(params.seed_priv));
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
  }

  /*
   * 테스트 : 유효하지 않은 상위인증서 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    memset(&params.issuer.octs, 0, sizeof(params.issuer.octs));
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
  }

  /*
   * 테스트 : 유효하지 않은 상위인증서 길이 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    params.issuer.size = kDot2CertSize_Min - 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);

    params.issuer.size = kDot2CertSize_Max + 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
  }

  /*
   * 테스트 : 유효하지 않은 인증서 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    memset(&params.certs[0].octs, 0, sizeof(params.certs[0].octs));
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
  }

  /*
   * 테스트 : 유효하지 않은 인증서 길이 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    params.certs[0].size = kDot2CertSize_Min - 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);

    params.certs[0].size = kDot2CertSize_Max + 1;
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
  }

  /*
   * 테스트 : 유효하지 않은 recon_priv 전달시 실패하는 것을 확인한다.
   */
  {
    params.i = i;
    params.j_max = j_max;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    for (int k = 0; k < DOT2_DEFAULT_P_CERTS_PER_I_PERIOD; k++) {
      memcpy(&params.certs[k], &certs[k], sizeof(struct Dot2Cert));
      memcpy(&params.recon_privs[k], &recon_privs[k], sizeof(struct Dot2ECPrivateKey));
    }
    memset(&params.recon_privs[0].octs, 0, sizeof(params.recon_privs[0].octs));
    res = Dot2_MakePseudonymCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
  }

  Dot2_Release();
}
