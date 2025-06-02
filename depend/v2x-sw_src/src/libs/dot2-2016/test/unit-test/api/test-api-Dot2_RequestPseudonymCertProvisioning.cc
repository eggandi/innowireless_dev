/**
  * @file
  * @brief Dot2_RequestPseudonymCertProvisioning() API 단위테스트
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
 * @brief 기본동작 테스트
 */
TEST(Dot2_RequestPseudonymCertProvisioning, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트 - 인증서발급요청을 정상적으로 처리하는 것을 확인한다.
   */
  {
    // 정상동작 확인
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(res.options.req);
    ASSERT_TRUE(res.options.ack);

    // 실행 중에 설정된 테스트벡터 값이 제대로 반환되는 것을 확인한다.
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.req_h8, g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, 8));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.verify_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_enc_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.verify_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cert_enc_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_EQ(res.options.ack_size, g_dot2_mib.lcm.test.https_resp_tv.resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.ack, g_dot2_mib.lcm.test.https_resp_tv.resp, res.options.ack_size));

    // 응용인증서발급응답문 테스트벡터로부터 추출된 정보가 테스트벡터와 일치하는지 확인한다.
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_dl_url, cert_dl_url, strlen(cert_dl_url)));
    ASSERT_EQ(res.common.cert_dl_time, cert_dl_time);

    free(res.common.cert_dl_url);
    free(res.options.req);
    free(res.options.ack);
  }

  /*
   * 테스트 - return_options=false일 때의 동작을 확인한다.
   */
  {
    // 정상동작 확인
    params.return_options = false;
    params.current_time = 0;
    params.start_time = 0;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);

    // 실행 중에 설정된 테스트벡터 값이 제대로 반환되는 것을 확인한다.
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.req_h8, g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, 8));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.verify_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_enc_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.verify_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cert_enc_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key.octs, DOT2_AES_128_LEN));

    // 응용인증서발급응답문 테스트벡터로부터 추출된 정보가 테스트벡터와 일치하는지 확인한다.
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_dl_url, cert_dl_url, strlen(cert_dl_url)));
    ASSERT_EQ(res.common.cert_dl_time, cert_dl_time);

    free(res.common.cert_dl_url);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_RequestPseudonymCertProvisioning, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 널 파라미터 전달
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;
    res = Dot2_RequestPseudonymCertProvisioning(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
  }

  Dot2_Release();
}


/**
 * @brief LCM 설정이 되지 않음
 */
TEST(Dot2_RequestPseudonymCertProvisioning, NO_LCM_CONFIG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정을 누락한다.

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;

    // LCM 정보 설정 없이 호출
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);

    // 일부 LCM 설정 후 호츨 -> RCA TLS 인증서경로가 설정되지 않은 상태
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);

    // 모든 필요 LCM 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(res.options.req);
    ASSERT_TRUE(res.options.ack);

    // 실행 중에 설정된 테스트벡터 값이 제대로 반환되는 것을 확인한다.
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.req_h8, g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, 8));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.verify_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_enc_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.verify_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cert_enc_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_EQ(res.options.ack_size, g_dot2_mib.lcm.test.https_resp_tv.resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.ack, g_dot2_mib.lcm.test.https_resp_tv.resp, res.options.ack_size));

    // 응용인증서발급응답문 테스트벡터로부터 추출된 정보가 테스트벡터와 일치하는지 확인한다.
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_dl_url, cert_dl_url, strlen(cert_dl_url)));
    ASSERT_EQ(res.common.cert_dl_time, cert_dl_time);

    free(res.common.cert_dl_url);
    free(res.options.req);
    free(res.options.ack);
  }

  Dot2_Release();
}


/**
 * @brief 등록인증서 CMHF가 등록되지 않음
 */
TEST(Dot2_RequestPseudonymCertProvisioning, NO_ENROL_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록을 누락한다.

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;

    // 등록인증서 CMHF 등록없이 호출
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);

    // 등록인증서 CMHF 등록 후 호출
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(res.options.req);
    ASSERT_TRUE(res.options.ack);

    // 실행 중에 설정된 테스트벡터 값이 제대로 반환되는 것을 확인한다.
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.req_h8, g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, 8));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.verify_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_enc_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.verify_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cert_enc_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_EQ(res.options.ack_size, g_dot2_mib.lcm.test.https_resp_tv.resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.ack, g_dot2_mib.lcm.test.https_resp_tv.resp, res.options.ack_size));

    // 응용인증서발급응답문 테스트벡터로부터 추출된 정보가 테스트벡터와 일치하는지 확인한다.
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_dl_url, cert_dl_url, strlen(cert_dl_url)));
    ASSERT_EQ(res.common.cert_dl_time, cert_dl_time);

    free(res.common.cert_dl_url);
    free(res.options.req);
    free(res.options.ack);
  }

  Dot2_Release();
}


/**
 * @brief PCA 인증서가 등록되지 않음
 */
TEST(Dot2_RequestPseudonymCertProvisioning, NO_PCA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록 - PCA를 등록하지 않음
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 4u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;

    // PCA 인증서 등록없이 호출
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);

    // PCA 인증서 등록 후 호출
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(res.options.req);
    ASSERT_TRUE(res.options.ack);

    // 실행 중에 설정된 테스트벡터 값이 제대로 반환되는 것을 확인한다.
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.req_h8, g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, 8));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.verify_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_enc_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.verify_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cert_enc_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_EQ(res.options.ack_size, g_dot2_mib.lcm.test.https_resp_tv.resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.ack, g_dot2_mib.lcm.test.https_resp_tv.resp, res.options.ack_size));

    // 응용인증서발급응답문 테스트벡터로부터 추출된 정보가 테스트벡터와 일치하는지 확인한다.
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_dl_url, cert_dl_url, strlen(cert_dl_url)));
    ASSERT_EQ(res.common.cert_dl_time, cert_dl_time);

    free(res.common.cert_dl_url);
    free(res.options.req);
    free(res.options.ack);
  }

  Dot2_Release();
}


/**
 * @brief RA 인증서가 등록되지 않음
 */
TEST(Dot2_RequestPseudonymCertProvisioning, NO_RA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록 - RA를 등록하지 않음
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_FALSE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 4u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;

    // RA 인증서 등록없이 호출
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);

    // RA 인증서 등록 후 호출
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(res.options.req);
    ASSERT_TRUE(res.options.ack);

    // 실행 중에 설정된 테스트벡터 값이 제대로 반환되는 것을 확인한다.
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.req_h8, g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, 8));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.verify_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_enc_priv_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key.octs, DOT2_EC_256_KEY_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.verify_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.cert_enc_exp_key.octs, g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key.octs, DOT2_AES_128_LEN));
    ASSERT_EQ(res.options.ack_size, g_dot2_mib.lcm.test.https_resp_tv.resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.ack, g_dot2_mib.lcm.test.https_resp_tv.resp, res.options.ack_size));

    // 응용인증서발급응답문 테스트벡터로부터 추출된 정보가 테스트벡터와 일치하는지 확인한다.
    ASSERT_TRUE(res.common.cert_dl_url);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cert_dl_url, cert_dl_url, strlen(cert_dl_url)));
    ASSERT_EQ(res.common.cert_dl_time, cert_dl_time);

    free(res.common.cert_dl_url);
    free(res.options.req);
    free(res.options.ack);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 응답문 메시지
 */
TEST(Dot2_RequestPseudonymCertProvisioning, INVALID_ACK_MSG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;

    // 테스트벡터 응답메시지의 길이를 최소길이보다 작게 설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = kDot2SPDUSize_Min - 1;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertProvisioningAck);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구

    // 테스트벡터 응답메시지의 길이를 최대길이보다 크게 설정한다.
    orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = kDot2SPDUSize_Max + 1;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertProvisioningAck);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구

    // 테스트벡터 응답메시지의 길이를 실제와 다르게 설정한다.
    orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size--;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertProvisioningAck);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구

    // 테스트벡터 요청메시지의 H8값을 강제 변경하여, 응답문 내 H8 값과 다르도록 만든다.
    g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8[0]++;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_DifferentCertProvisioningAckRequestHash);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8[0]--; // 원상복구

    // 테스트벡터 응답메시지의 서명을 강제 변조한다.
    g_dot2_mib.lcm.test.https_resp_tv.resp[g_dot2_mib.lcm.test.https_resp_tv.resp_size - 1]++;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_SignatureVerificationFailed);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.resp[g_dot2_mib.lcm.test.https_resp_tv.resp_size - 1]--; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 응답문 수신 오류
 */
TEST(Dot2_RequestPseudonymCertProvisioning, ACK_MSG_RX_ERROR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertProvisioningRequestParams params{};
  struct Dot2PseudonymIdCertProvisioningRequestResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, pc[20];
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv[20], priv_key[20];
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_prov_resp_cert_dl_url;
  char cert_filename[20][100] = {}, priv_key_filename[20][100] = {}, recon_priv_filename[20][100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char pc_cmhf_name[100] = {};
  uint8_t pc_cmhf[5000];
  size_t pc_cmhf_size;
  char down_dirname[50] = {};

  /*
   * 준비
   */
  {
    // 공통 테스트벡터 바이트열 변환
    ASSERT_EQ(ec.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cert, ec.octs), g_tv_bluetech_ec_resp_enrol_cert_size);
    ASSERT_EQ(eca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_eca, eca.octs), g_tv_bluetech_eca_size);
    ASSERT_EQ(ra.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ra, ra.octs), g_tv_bluetech_ra_size);
    ASSERT_EQ(rca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_rca, rca.octs), g_tv_bluetech_rca_size);
    ASSERT_EQ(crlg.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_crlg, crlg.octs), g_tv_bluetech_crlg_size);
    ASSERT_EQ(ica.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ica, ica.octs), g_tv_bluetech_ica_size);
    ASSERT_EQ(pca.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pca, pca.octs), g_tv_bluetech_pca_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);

    // 익명인증서 발급요청 관련 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_req_filename_1A9);
    strcpy(pc_cmhf_name, g_tv_bluetech_pseudonym_cert_down_cmhf_name_1A9);
    strcpy(down_dirname, g_tv_bluetech_pseudonym_cert_down_dir_name_1A9);
    for (unsigned int i = 0; i < 20; i++) {
      strcpy(cert_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_filename);
      strcpy(priv_key_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key_filename);
      strcpy(recon_priv_filename[i], g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv_filename);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].priv_key, priv_key[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].recon_priv, recon_priv[i].octs), DOT2_EC_256_KEY_LEN);
      ASSERT_EQ(pc[i].size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_1A9[i].cert, pc[i].octs), g_tv_bluetech_pseudonym_cert_down_1A9[i].cert_size);
    }
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_resp, prov_resp), g_tv_bluetech_pseudonym_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_zipfile_1A9, zipfile), g_tv_bluetech_pseudonym_cert_down_zipfile_size_1A9);
    ASSERT_EQ(pc_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_cmhf_1A9, pc_cmhf), g_tv_bluetech_pseudonym_cert_down_cmhf_size_1A9);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, g_tv_bluetech_pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.pseudonym_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.pseudonym_cert.tv.prov_req_h8, prov_req_h8, 8);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, prov_resp, prov_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = prov_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    params.current_time = 0;
    params.start_time = 0;

    // CURL 실행 결과를 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_UNSUPPORTED_PROTOCOL;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_curl_easy_perform);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK; // 원상복구

    // 수신되는 HTTP CODE 값을 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK; // 원상복구

    // 수신되는 응답메시지의 길이를 0으로 강제설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_RequestPseudonymCertProvisioning(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.common.cert_dl_url);
    ASSERT_FALSE(res.options.req);
    ASSERT_FALSE(res.options.ack);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구
  }

  Dot2_Release();
}
