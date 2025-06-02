/**
  * @file
  * @brief Dot2_ProcessECResponse() API 단위테스트
  * @date 2023-02-26
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
TEST(Dot2_ProcessECResponse, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECResponseProcessParams params{};
  struct Dot2ECResponseProcessResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  Dot2ECPrivateKey init_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_req_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
  }

  /*
   * 테스트 - ECResponse를 정상적으로 처리하는 것을 확인한다.
   */
  {
    // 정상동작 확인
    params.ec_resp = nullptr; // 블루텍 서버는 ECResponse가 수신되지 않는다.
    memcpy(&params.ec, &ec, sizeof(ec));
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.eca_cert, &eca, sizeof(eca));
    memcpy(&params.ra_cert, &ra, sizeof(ra));
    memcpy(&params.rca_cert, &rca, sizeof(rca));
    params.lccf = lccf;
    params.lccf_size = lccf_size;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.enrollment_cmhf_name);
    ASSERT_TRUE(res.enrollment_cmhf);
    ASSERT_TRUE(res.rca_cert);
    ASSERT_TRUE(res.ica_cert);
    ASSERT_TRUE(res.pca_cert);
    ASSERT_TRUE(res.crlg_cert);
    ASSERT_EQ(res.enrollment_cmf_size, ec_cmhf_size);
    ASSERT_EQ(res.rca_cert_size, rca.size);
    ASSERT_EQ(res.ica_cert_size, ica.size);
    ASSERT_EQ(res.pca_cert_size, pca.size);
    ASSERT_EQ(res.crlg_cert_size, crlg.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.enrollment_priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.enrollment_cmhf_name, ec_cmhf_name, strlen(ec_cmhf_name)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.enrollment_cmhf, ec_cmhf, ec_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.rca_cert, rca.octs, rca.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ica_cert, ica.octs, ica.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.pca_cert, pca.octs, pca.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.crlg_cert, crlg.octs, crlg.size));
    free(res.enrollment_cmhf_name);
    free(res.enrollment_cmhf);
    free(res.rca_cert);
    free(res.ica_cert);
    free(res.pca_cert);
    free(res.crlg_cert);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_ProcessECResponse, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECResponseProcessParams params{};
  struct Dot2ECResponseProcessResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  Dot2ECPrivateKey init_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_req_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.ec_resp = nullptr; // 블루텍 서버는 ECResponse가 수신되지 않는다.
    memcpy(&params.ec, &ec, sizeof(ec));
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.eca_cert, &eca, sizeof(eca));
    memcpy(&params.ra_cert, &ra, sizeof(ra));
    memcpy(&params.rca_cert, &rca, sizeof(rca));
    params.lccf = lccf;
    params.lccf_size = lccf_size;

    // 널 파라미터 전달
    res = Dot2_ProcessECResponse(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);

    // 유효하지 않은 ECResponse 길이 - 파라미터 유효성만 체크하므로 임의의 바이트열을 ECResponse로 전달한다.
    params.ec_resp = ec_cmhf;
    params.ec_resp_size = kDot2SPDUSize_Min - 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidSPDUSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.ec_resp_size = kDot2SPDUSize_Max + 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidSPDUSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.ec_resp = nullptr; // 원상복구

    // 유효하지 않은 ECResponse - 유효하지 않은 바이트열을 ECResponse로 전달한다.
    params.ec_resp = ec_cmhf;
    params.ec_resp_size = 100;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeECResponse);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.ec_resp = nullptr; // 원상복구

    // 너무 짧은 인증서 사이즈
    params.rca_cert.size = kDot2CertSize_Min - 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.rca_cert, &rca, sizeof(rca)); // 원상복구
    params.ra_cert.size = kDot2CertSize_Min - 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.ra_cert, &ra, sizeof(ra)); // 원상복구
    params.eca_cert.size = kDot2CertSize_Min - 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.eca_cert, &eca, sizeof(eca)); // 원상복구
    params.ec.size = kDot2CertSize_Min - 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.ec, &ec, sizeof(ec)); // 원상복구

    // 너무 긴 인증서 사이즈
    params.rca_cert.size = kDot2CertSize_Max + 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.rca_cert, &rca, sizeof(rca)); // 원상복구
    params.ra_cert.size = kDot2CertSize_Max + 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.ra_cert, &ra, sizeof(ra)); // 원상복구
    params.eca_cert.size = kDot2CertSize_Max + 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.eca_cert, &eca, sizeof(eca)); // 원상복구
    params.ec.size = kDot2CertSize_Max + 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    memcpy(&params.ec, &ec, sizeof(ec)); // 원상복구

    // 널 LCCF
    params.lccf = nullptr;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.lccf = lccf; // 원상복구

    // 유효하지 않은 LCCF
    params.lccf_size--;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeLCCF);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.lccf_size++; // 원상복구

    // 너무 긴 LCCF 사이즈
    params.lccf_size = kDot2LCCFSize_Max + 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidLCCFSize);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.lccf_size = lccf_size; // 원상복구

    // 유효하지 않은 임시 개인키
    params.init_priv_key.octs[0]++;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.init_priv_key.octs[0]--; // 원상복구

    // 유효하지 않은 개인키재구성값
    params.recon_priv.octs[0]++;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.recon_priv.octs[0]--; // 원상복구

    // 유효하지 않은 등록인증서
    params.ec.size--;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.ec.size++; // 원상복구

    // 유효하지 않은 ECA 인증서
    params.eca_cert.size--;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertificate);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);
    params.eca_cert.size++; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief LCCF 내 SCC 인증서 저장 실패
 */
TEST(Dot2_ProcessECResponse, ADD_SCC_CERTS_FAIL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2ECResponseProcessParams params{};
  struct Dot2ECResponseProcessResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  Dot2ECPrivateKey init_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_resp[kDot2SPDUSize_Max];

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_req_init_priv_key, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
  }

  /*
   * 테스트
   */
  {
    unsigned int orig_max_entry_num = g_dot2_mib.scc_cert_info_table.scc.max_entry_num;

    // 파라미터 설정
    params.ec_resp = nullptr; // 블루텍 서버는 ECResponse가 수신되지 않는다.
    memcpy(&params.ec, &ec, sizeof(ec));
    memcpy(&params.init_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.recon_priv, &recon_priv, sizeof(recon_priv));
    memcpy(&params.eca_cert, &eca, sizeof(eca));
    memcpy(&params.ra_cert, &ra, sizeof(ra));
    memcpy(&params.rca_cert, &rca, sizeof(rca));
    params.lccf = lccf;
    params.lccf_size = lccf_size;

    // SCC 인증서 저장소의 최대 저장 개수를 0으로 설정하여 실패하도록 한다. (테스트벡터 LCCF는 4개의 SCC 인증서가 들어 있다)
    g_dot2_mib.scc_cert_info_table.scc.max_entry_num = 0;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_TooManyCertsInTable);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);

    // SCC 인증서 저장소의 최대 저장 개수를 1으로 설정하여 실패하도록 한다. (테스트벡터 LCCF는 4개의 SCC 인증서가 들어 있다)
    g_dot2_mib.scc_cert_info_table.scc.max_entry_num = 1;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_TooManyCertsInTable);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);

    // SCC 인증서 저장소의 최대 저장 개수를 2으로 설정하여 실패하도록 한다. (테스트벡터 LCCF는 4개의 SCC 인증서가 들어 있다)
    g_dot2_mib.scc_cert_info_table.scc.max_entry_num = 2;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_TooManyCertsInTable);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);

    // SCC 인증서 저장소의 최대 저장 개수를 3으로 설정하여 실패하도록 한다. (테스트벡터 LCCF는 4개의 SCC 인증서가 들어 있다)
    g_dot2_mib.scc_cert_info_table.scc.max_entry_num = 0;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, -kDot2Result_TooManyCertsInTable);
    ASSERT_FALSE(res.enrollment_cmhf_name);
    ASSERT_FALSE(res.enrollment_cmhf);
    ASSERT_FALSE(res.rca_cert);
    ASSERT_FALSE(res.ica_cert);
    ASSERT_FALSE(res.pca_cert);
    ASSERT_FALSE(res.crlg_cert);

    // SCC 인증서 저장소의 최대 저장 개수를 복구하여 성공하도록 한다. (테스트벡터 LCCF는 4개의 SCC 인증서가 들어 있다)
    g_dot2_mib.scc_cert_info_table.scc.max_entry_num = orig_max_entry_num;
    res = Dot2_ProcessECResponse(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.enrollment_cmhf_name);
    ASSERT_TRUE(res.enrollment_cmhf);
    ASSERT_TRUE(res.rca_cert);
    ASSERT_TRUE(res.ica_cert);
    ASSERT_TRUE(res.pca_cert);
    ASSERT_TRUE(res.crlg_cert);
    ASSERT_EQ(res.enrollment_cmf_size, ec_cmhf_size);
    ASSERT_EQ(res.rca_cert_size, rca.size);
    ASSERT_EQ(res.ica_cert_size, ica.size);
    ASSERT_EQ(res.pca_cert_size, pca.size);
    ASSERT_EQ(res.crlg_cert_size, crlg.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.enrollment_priv_key.octs, priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.enrollment_cmhf_name, ec_cmhf_name, strlen(ec_cmhf_name)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.enrollment_cmhf, ec_cmhf, ec_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.rca_cert, rca.octs, rca.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.ica_cert, ica.octs, ica.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.pca_cert, pca.octs, pca.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.crlg_cert, crlg.octs, crlg.size));
    free(res.enrollment_cmhf_name);
    free(res.enrollment_cmhf);
    free(res.rca_cert);
    free(res.ica_cert);
    free(res.pca_cert);
    free(res.crlg_cert);
  }

  Dot2_Release();
}
