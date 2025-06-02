/**
 * @file
 * @brief Dot2_MakeIdentificationCertCMHF() API 테스트
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
 * @brief 기본동작
 */
TEST(Dot2_MakeIdentificationCertCMHF, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2IdCMHFMakeParams params{};
  struct Dot2IdCMHFMakeResult res{};
  uint32_t i;
  struct Dot2AESKey exp_key{};
  struct Dot2ECPrivateKey seed_priv{}, priv_key{}, recon_priv{};
  struct Dot2Cert cert{}, issuer{};
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;
  const char *cmhf_name = g_tv_bundle_1_id_cert_0_cmhf_name;

  memset(&params, 0, sizeof(params));

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_expansion_key, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_seed_priv_key, seed_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0, cert.octs), (size_t)g_tv_bundle_1_id_cert_0_size);
    ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca, issuer.octs), (size_t)g_tv_bundle_1_pca_size);
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_1_id_cert_0_cmhf_size);
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 생성된 CMHF 확인
   */
  {
    // API 호출
    params.i = 0;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.cert, &cert, sizeof(struct Dot2Cert));
    memcpy(&params.recon_priv, &recon_priv, sizeof(struct Dot2ECPrivateKey));
    memcpy(&params.issuer, &issuer, sizeof(issuer));
    res = Dot2_MakeIdentificationCertCMHF(&params);

    // 결과 확인
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.cmhf_name);
    ASSERT_TRUE(res.cmhf);
    ASSERT_EQ(res.cmhf_size, (size_t)cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cmhf_name, cmhf_name, strlen(cmhf_name)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cmhf, cmhf, cmhf_size));
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터
 */
TEST(Dot2_MakeIdentificationCertCMHF, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2IdCMHFMakeParams params{};
  struct Dot2IdCMHFMakeResult res{};
  uint32_t i;
  struct Dot2AESKey exp_key{};
  struct Dot2ECPrivateKey seed_priv{}, priv_key{}, recon_priv{};
  struct Dot2Cert cert{}, issuer{};
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;
  const char *cmhf_name = g_tv_bundle_1_id_cert_0_cmhf_name;

  memset(&params, 0, sizeof(params));

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_expansion_key, exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_seed_priv_key, seed_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0, cert.octs), (size_t)g_tv_bundle_1_id_cert_0_size);
    ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca, issuer.octs), (size_t)g_tv_bundle_1_pca_size);
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_1_id_cert_0_cmhf_size);
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.i = 0;
    memcpy(&params.exp_key, &exp_key, sizeof(exp_key));
    memcpy(&params.seed_priv, &seed_priv, sizeof(seed_priv));
    memcpy(&params.cert, &cert, sizeof(struct Dot2Cert));
    memcpy(&params.recon_priv, &recon_priv, sizeof(struct Dot2ECPrivateKey));
    memcpy(&params.issuer, &issuer, sizeof(issuer));

    // 널파라미터 전달
    res = Dot2_MakeIdentificationCertCMHF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);

    // 유효하지 않은 인증서 길이
    params.cert.size = kDot2CertSize_Min - 1;
    res = Dot2_MakeIdentificationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
    params.cert.size = kDot2CertSize_Max + 1;
    res = Dot2_MakeIdentificationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
    params.cert.size = cert.size; // 원상복구

    // 유효하지 않은 상위인증서 길이
    params.issuer.size = kDot2CertSize_Min - 1;
    res = Dot2_MakeIdentificationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
    params.issuer.size = kDot2CertSize_Max + 1;
    res = Dot2_MakeIdentificationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
    params.issuer.size = cert.size; // 원상복구

    // 유효하지 않은 인증서
    params.cert.size--;
    res = Dot2_MakeIdentificationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
    params.cert.size++; // 원상복구

    // 유효하지 않은 상위인증서
    params.issuer.size--;
    res = Dot2_MakeIdentificationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
    params.issuer.size++; // 원상복구
  }

  Dot2_Release();
}
