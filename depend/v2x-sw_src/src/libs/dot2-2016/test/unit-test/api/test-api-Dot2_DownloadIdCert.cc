/**
  * @file
  * @brief Dot2_DownloadIdCert() API 단위테스트
  * @date 2023-03-06
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


#if 0 // 테스트벡터로 사용되는 블루텍 ID 인증서가 변경되어야 한다 - 과거 i 값이 잘못되어 있던 인증서인 듯 하다.
/**
 * @brief 기본동작 테스트
 */
TEST(Dot2_DownloadIdCert, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 정상동작 확인
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);

    // 실행 중에 저장된 테스트벡터 값이 정상인 것을 확인한다
    // 실행 중간 단계에서 생성된 정보의 유효성 확인 (최종단계에서의 확인이 어려운 경우를 위해)
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));

    // 반환된 CMHF 정보 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));

    // 반환된 옵션정보 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, cert_filename, strlen(cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ic.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ic.octs, ic.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));

    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  /*
   * 테스트 - return_options=false일 때의 동작을 확인한다.
   */
  {
    // 정상동작 확인
    params.return_options = false;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);

    // 실행 중에 저장된 테스트벡터 값이 정상인 것을 확인한다
    // 실행 중간 단계에서 생성된 정보의 유효성 확인 (최종단계에서의 확인이 어려운 경우를 위해)
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));

    // 반환된 CMHF 정보 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));

    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_DownloadIdCert, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // 널 파라미터 전달
    res = Dot2_DownloadIdCert(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 잘못된 다운로드요청문 H8 값 -> 요청문의 유효성은 서버가 판단하므로 여기서는 실패 여부를 알 수 없다.
    params.common.req_h8[0]++;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    free(res.common.cmhf_name);
    free(res.common.cmhf);
    params.common.req_h8[0]--; // 원상복구

    // 잘못된 서명용 임시 개인키
    params.common.verify_priv_key.octs[0]++;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.common.verify_priv_key.octs[0]--; // 원상복구

    // 잘못된 인증서암호화용 개인키
    params.common.cert_enc_priv_key.octs[0]++;;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_DecryptCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.common.cert_enc_priv_key.octs[0]--; // 원상복구

    // 널 인증서다운로드 URL
    params.common.cert_dl_url = nullptr;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.common.cert_dl_url = (char *)cert_dl_url; // 원상복구

    // 잘못된 서명용 확장키
    params.verify_exp_key.octs[0]++;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.verify_exp_key.octs[0]--; // 원상복구

    // 잘못된 인증서암호화용 확장키
    params.cert_enc_exp_key.octs[0]++;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_DecryptCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.cert_enc_exp_key.octs[0]--; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 LCM 설정
 */
TEST(Dot2_DownloadIdCert, INVALID_LCM_CONFIG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

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
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // LCM 정보 설정 없이 호출
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 일부 LCM 설정 후 호츨 -> 임시압축파일저장경로가 설정되지 않은 상태
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 임시압축파일저장경로를 잘못된 경로로 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, "/no/no"), kDot2Result_Success);
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_FILE_Access);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 모든 필요 LCM 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, cert_filename, strlen(cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ic.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ic.octs, ic.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));
    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 등록인증서 CMHF가 등록되지 않음
 */
TEST(Dot2_DownloadIdCert, NO_ENROL_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록을 누락한다.

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // 등록인증서 CMHF 등록없이 호출
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 등록인증서 CMHF 등록 후 호출
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, cert_filename, strlen(cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ic.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ic.octs, ic.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));
    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief PCA 인증서가 등록되지 않음
 */
TEST(Dot2_DownloadIdCert, NO_PCA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록 - PCA를 등록하지 않음
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 4u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // PCA 인증서 등록없이 호출
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // PCA 등록 후 호출
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, cert_filename, strlen(cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ic.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ic.octs, ic.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));
    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief RA 인증서가 등록되지 않음
 */
TEST(Dot2_DownloadIdCert, NO_RA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록 - RA를 등록하지 않음
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_FALSE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 4u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // RA 인증서 등록없이 호출
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // RA 등록 후 호출
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, cert_filename, strlen(cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ic.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ic.octs, ic.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));
    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 다운로드응답문(ZIP 파일)
 */
TEST(Dot2_DownloadIdCert, INVALID_DOWN_ZIP_FILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // 테스트벡터 다운로드 ZIP파일의 길이를 실제와 다르게 설정한다.
    size_t orig_zipfile_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size--;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_FILE_Unzip);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_zipfile_size; // 원상복구

    // 다운로드 ZIP 파일 내 첫번째 다운로드응답문의 길이를 유효하지 않게 설정한다.
    // 최소길이보다 짧게 설정한다. 최대길이보다 크게는 설정할 수 없다(내부에서 테스트벡터값으로 복사하면서 오버플로우 발생)
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = true;
    size_t orig_size = g_dot2_mib.lcm.test.id_cert.tv.down_resp_size;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = kDot2SPDUSize_Min - 1;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = orig_size; // 원상복구

    // 다운로드 ZIP 파일 내 첫번째 다운로드응답문의 길이를 실제와 다르게 설정한다.
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = true;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size--;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size++; // 원상복구

    // 다운로드 ZIP 파일 내 첫번째 다운로드응답문의 서명을 변조한다. (서명은 응답문의 마지막에 수납되어 있다)
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = true;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp[g_dot2_mib.lcm.test.id_cert.tv.down_resp_size - 1]++;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_SignatureVerificationFailed);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.id_cert.tv.down_resp[g_dot2_mib.lcm.test.id_cert.tv.down_resp_size - 1]--; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 응답문 수신 오류
 */
TEST(Dot2_DownloadIdCert, DOWN_RESP_MSG_RX_ERROR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_0_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_0);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_0);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_0);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_0.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_0.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_0.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_0.cert, ic.octs), g_tv_bluetech_id_cert_down_0.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_0, down_resp), g_tv_bluetech_id_cert_down_resp_size_0);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_0, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_0);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_0, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_0);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 0;

    // CURL 실행 결과를 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_UNSUPPORTED_PROTOCOL;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_curl_easy_perform);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK; // 원상복구

    // 수신되는 HTTP CODE 값을 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_NOT_MODIFIED;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoModifiedFile);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_DownloadInfoUnvailable);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_ServerError);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = 0;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK; // 원상복구

    // 수신되는 응답메시지의 길이를 0으로 강제설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief i-period != 0 테스트 (i_period = 0은 이번주를 나타낸다)
 */
TEST(Dot2_DownloadIdCert, NON_ZERO_I_PERIOD)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2PseudonymIdCertDownloadRequestParams params{};
  struct Dot2IdCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ic{};
  Dot2ECPrivateKey init_priv_key{}, enc_key{}, recon_priv{}, priv_key{};
  Dot2AESKey verify_exp_key{}, enc_exp_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  Dot2Time32 cert_dl_time = g_tv_bluetech_id_cert_prov_resp_cert_dl_time;
  const char *cert_dl_url = g_tv_bluetech_id_cert_prov_resp_cert_dl_url;
  char cert_filename[100] = {}, priv_key_filename[100] = {}, recon_priv_filename[100] = {};
  uint8_t prov_req_h8[8];
  uint8_t prov_resp[1000];
  size_t prov_resp_size;
  char req_filename[100] = {};
  uint8_t zipfile[10000];
  size_t zipfile_size;
  char ic_cmhf_name[100] = {};
  uint8_t ic_cmhf[5000];
  size_t ic_cmhf_size;
  char down_dirname[50] = {};
  uint8_t down_resp[500];
  size_t down_resp_size;
  unsigned int i_period = g_tv_bluetech_id_cert_down_req_1_i_period;

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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_priv, init_priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_priv, enc_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_initial_verify_key_exp, verify_exp_key.octs), DOT2_AES_128_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_encryption_key_exp, enc_exp_key.octs), DOT2_AES_128_LEN);
    strcpy(req_filename, g_tv_bluetech_id_cert_down_req_filename_1);
    strcpy(ic_cmhf_name, g_tv_bluetech_id_cert_down_cmhf_name_1);
    strcpy(down_dirname, g_tv_bluetech_id_cert_down_dir_name_1);
    strcpy(cert_filename, g_tv_bluetech_id_cert_down_1.cert_filename);
    strcpy(priv_key_filename, g_tv_bluetech_id_cert_down_1.priv_key_filename);
    strcpy(recon_priv_filename, g_tv_bluetech_id_cert_down_1.recon_priv_filename);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_1.priv_key, priv_key.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_1.recon_priv, recon_priv.octs), DOT2_EC_256_KEY_LEN);
    ASSERT_EQ(ic.size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_1.cert, ic.octs), g_tv_bluetech_id_cert_down_1.cert_size);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_resp_1, down_resp), g_tv_bluetech_id_cert_down_resp_size_1);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(prov_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_prov_resp, prov_resp), g_tv_bluetech_id_cert_prov_resp_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_zipfile_1, zipfile), g_tv_bluetech_id_cert_down_zipfile_size_1);
    ASSERT_EQ(ic_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_id_cert_down_cmhf_1, ic_cmhf), g_tv_bluetech_id_cert_down_cmhf_size_1);

    // SCC 인증서 등록
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_key.priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_key.priv_key), &enc_key, sizeof(enc_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(g_dot2_mib.lcm.test.id_cert.tv.encryption_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.prov_req_h8, prov_req_h8, 8);
    g_dot2_mib.lcm.test.id_cert.tv.i_period = i_period;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.id_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.id_cert.tv.down_resp, down_resp, down_resp_size);
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트 - i-period=1일 때의 동작을 확인한다. (i-period=1은 다음달을 나타낸다)
   */
  {
    // 정상동작 확인
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&(params.common.verify_priv_key), &init_priv_key, sizeof(init_priv_key));
    memcpy(&(params.common.cert_enc_priv_key), &enc_key, sizeof(enc_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    memcpy(&(params.verify_exp_key), &verify_exp_key, sizeof(verify_exp_key));
    memcpy(&(params.cert_enc_exp_key), &enc_exp_key, sizeof(enc_exp_key));
    params.target_time = 1;
    res = Dot2_DownloadIdCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.id_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.id_cert.res.down_resp, down_resp, down_resp_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, ic_cmhf_name, strlen(ic_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, ic_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, ic_cmhf, ic_cmhf_size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, cert_filename, strlen(cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ic.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ic.octs, ic.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));
    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}
#endif
