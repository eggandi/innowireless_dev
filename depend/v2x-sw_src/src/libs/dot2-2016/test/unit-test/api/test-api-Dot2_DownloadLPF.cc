/**
  * @file
  * @brief Dot2_DownloadLPF() API 단위테스트
  * @date 2023-03-01
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief 기본동작 테스트 (현재파일이 없는 상태)
 */
TEST(Dot2_DownloadLPF, NO_CURRENT_FILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파일명 전달하지 않음
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.lpf_filename);
    ASSERT_TRUE(res.lpf);
    ASSERT_EQ(res.lpf_size, lpf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf_filename, lpf_filename, strlen(lpf_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf, lpf, lpf_size));
    free(res.lpf_filename);
    free(res.lpf);
  }

  Dot2_Release();
}


/**
 * @brief 기본동작 테스트 (최신파일이 있는 상태)
 */
TEST(Dot2_DownloadLPF, LATEST_FILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_not_modified_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[0], g_tv_bluetech_lpf_resp_hdr_not_modified);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_NOT_MODIFIED;
  }

  /*
   * 테스트
   */
  {
    // 최신파일명 전달
    res = Dot2_DownloadLPF(lpf_filename);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoModifiedFile);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
  }

  Dot2_Release();
}


/**
 * @brief 기본동작 테스트 (최신파일이 없는 상태)
 */
TEST(Dot2_DownloadLPF, NO_LATEST_FILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 최신파일이 아닌 파일이름을 전달
    res = Dot2_DownloadLPF("local_certificate_chains_01_00.oer");
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.lpf_filename);
    ASSERT_TRUE(res.lpf);
    ASSERT_EQ(res.lpf_size, lpf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf_filename, lpf_filename, strlen(lpf_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf, lpf, lpf_size));
    free(res.lpf_filename);
    free(res.lpf);
  }

  Dot2_Release();
}


/**
 * @brief LCM 설정이 되지 않음
 */
TEST(Dot2_DownloadLPF, NO_LCM_CONFIG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정을 누락한다.

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // LCM 정보 설정 없이 호출
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);

    // 일부 LCM 설정 후 호츨 -> LPF 요청 URL이 설정되지 않은 상태
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);

    // 모든 필요 LCM 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.lpf_filename);
    ASSERT_TRUE(res.lpf);
    ASSERT_EQ(res.lpf_size, lpf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf_filename, lpf_filename, strlen(lpf_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf, lpf, lpf_size));
    free(res.lpf_filename);
    free(res.lpf);
  }

  Dot2_Release();
}


/**
 * @brief 서버로부터 수신한 Response 헤더에 filename 정보가 없는 경우
 */
TEST(Dot2_DownloadLPF, NO_FILE_NAME_IN_RESP_HDR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // filename 정보가 들어 있지 않은 Response 헤더로 강제 교체한다.
    strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[3], g_tv_bluetech_lpf_resp_hdr_no_filename);
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoKeyValueInHeader);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
  }

  Dot2_Release();
}


/**
 * @brief 서버로부터 수신한 Response 헤더에 수납된 filename이 빈 문자열인 경우
 */
TEST(Dot2_DownloadLPF, EMPTY_FILE_NAME_IN_RESP_HDR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 빈 문자열인 filename 정보가 들어 있는 Response 헤더로 강제 교체한다.
    strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[3], g_tv_bluetech_lpf_resp_hdr_empty_filename);
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidFileNameLenInHeader);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 LPF 수신
 */
TEST(Dot2_DownloadLPF, INVALID_RX_LPF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 수신 LPF의 길이를 실제와 다르게 설정한다. (LPF가 끝까지 다 수신되지 않은 경우)
    // 현재 libdot2는 수신된 LPF를 따로 처리 하지는 않으므로 수신된 그대로 반환된다.
    g_dot2_mib.lcm.test.https_resp_tv.resp_size--;
    lpf_size--;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.lpf_filename);
    ASSERT_TRUE(res.lpf);
    ASSERT_EQ(res.lpf_size, lpf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf_filename, lpf_filename, strlen(lpf_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf, lpf, lpf_size));
    free(res.lpf_filename);
    free(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size++; // 원상복구
    lpf_size++; // 원상복구

    // 0 바이트 LPF를 수신한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구

    // 변조된 수신 LPF를 수신한다.
    // 현재 libdot2는 수신된 LPF를 따로 처리 하지는 않으므로 수신된 그대로 반환된다.
    g_dot2_mib.lcm.test.https_resp_tv.resp[1]++;
    lpf[1]++;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.lpf_filename);
    ASSERT_TRUE(res.lpf);
    ASSERT_EQ(res.lpf_size, lpf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf_filename, lpf_filename, strlen(lpf_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.lpf, lpf, lpf_size));
    free(res.lpf_filename);
    free(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.resp[1]--; // 원상복구
    lpf[1]--; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief LPF 수신 오류
 */
TEST(Dot2_DownloadLPF, LPF_RX_ERROR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2LPFRequestResult res{};

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  const char *lpf_filename = g_tv_bluetech_lpf_filename;
  uint8_t lpf[kDot2SPDUSize_Max];
  Dot2SPDUSize lpf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;

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
    ASSERT_EQ(ac.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cert, ac.octs), g_tv_bluetech_app_cert_down_cert_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_encryption_key_priv, enc_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(lpf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lpf, lpf), g_tv_bluetech_lpf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_tv_bluetech_lpf_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, lpf, lpf_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = lpf_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num = g_tv_bluetech_lpf_resp_hdr_num;
    memset(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr, 0, sizeof(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr));
    for (unsigned int i = 0; i < g_tv_bluetech_lpf_resp_hdr_num; i++) {
      strcpy(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i], g_tv_bluetech_lpf_resp_hdr[i]);
    }
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // CURL 실행 결과를 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_UNSUPPORTED_PROTOCOL;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_curl_easy_perform);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK; // 원상복구

    // 수신되는 HTTP CODE 값을 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_NOT_MODIFIED;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoModifiedFile);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_DownloadInfoUnvailable);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_ServerError);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = 0;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK; // 원상복구

    // 수신되는 응답메시지의 길이를 0으로 강제설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_DownloadLPF(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.lpf_filename);
    ASSERT_FALSE(res.lpf);
  }

  Dot2_Release();
}
