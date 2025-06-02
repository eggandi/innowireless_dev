/**
 * @file
 * @brief Dot2_MakeApplicationCertCMHF() API 테스트
 * @date 2022-08-03
 * @author gyun
 */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief 기본동작 테스트
 */
TEST(Dot2_MakeApplicationCertCMHF, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCMHFMakeParams params{};
  struct Dot2CMHFMakeResult res{};
  struct Dot2ECPrivateKey init_priv_key{}, recon_priv{}, priv_key{};
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  memset(&params, 0, sizeof(params));

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(params.cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0, params.cert.octs), (size_t)g_tv_bundle_0_app_cert_0_size);
    ASSERT_EQ(params.issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, params.issuer.octs), (size_t)g_tv_bundle_0_pca_size);
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 생성된 CMHF 확인
   */
  {
    // API 호출
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    res = Dot2_MakeApplicationCertCMHF(&params);

    // 결과 확인
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.cmhf_name);
    ASSERT_TRUE(res.cmhf);
    ASSERT_EQ(res.cmhf_size, (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cmhf_name, g_tv_bundle_0_app_cert_0_cmhf_name, strlen(g_tv_bundle_0_app_cert_0_cmhf_name)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cmhf, cmhf, cmhf_size));

    free(res.cmhf_name);
    free(res.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_MakeApplicationCertCMHF, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCMHFMakeParams params{};
  struct Dot2CMHFMakeResult res{};
  struct Dot2ECPrivateKey init_priv_key{}, recon_priv{}, priv_key{};
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;
  Dot2Cert cert{}, issuer{};

  memset(&params, 0, sizeof(params));

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(cert.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0, cert.octs), (size_t)g_tv_bundle_0_app_cert_0_size);
    ASSERT_EQ(issuer.size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, issuer.octs), (size_t)g_tv_bundle_0_pca_size);
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);
  }

  /*
   * 테스트 : 널 파라미터 전달시 실패하는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    res = Dot2_MakeApplicationCertCMHF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
  }

  /*
   * 테스트 : 유효하지 않은 초기개인키 전달 시 비정상적인 개인키가 도출되는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    params.init_priv_key.octs[0]++;
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
  }

  /*
   * 테스트 : 유효하지 않은 개인키재구성값 전달 시 비정상적인 개인키가 도출되는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    params.recon_priv.octs[0]++;
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
    //ASSERT_FALSE(Dot2Test_CompareOctets(res.priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
  }

  /*
   * 테스트 : 유효하지 않은 인증서 전달 시 실패하는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    memset(params.cert.octs, 0, sizeof(params.cert.octs));
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
  }

  /*
   * 테스트 : 유효하지 않은 인증서 길이 전달 시 실패하는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    params.cert.size = kDot2CertSize_Min - 1;
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
    params.cert.size = kDot2CertSize_Max + 1;
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
  }

  /*
   * 테스트 : 유효하지 않은 상위인증서 전달 시 실패하는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    memset(params.issuer.octs, 0, sizeof(params.issuer.octs));
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
  }

  /*
   * 테스트 : 유효하지 않은 인증서 길이 전달 시 실패하는 것을 확인한다.
   */
  {
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.cert, &cert, sizeof(Dot2Cert));
    memcpy(&params.issuer, &issuer, sizeof(Dot2Cert));
    params.issuer.size = kDot2CertSize_Min - 1;
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
    params.issuer.size = kDot2CertSize_Max + 1;
    res = Dot2_MakeApplicationCertCMHF(&params);
    ASSERT_EQ(res.ret, -kDot2Result_CERT_InvalidCertSize);
  }

  Dot2_Release();
}
