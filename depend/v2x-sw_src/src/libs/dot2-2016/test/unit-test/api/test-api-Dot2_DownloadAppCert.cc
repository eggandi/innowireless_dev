/**
  * @file
  * @brief Dot2_DownloadAppCert() API 단위테스트
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
TEST(Dot2_DownloadAppCert, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
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
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);

    // 실행 중에 저장된 테스트벡터 값이 정상인 것을 확인한다
    // 실행 중간 단계에서 생성된 정보의 유효성 확인 (최종단계에서의 확인이 어려운 경우를 위해)
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.app_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.app_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.app_cert.res.down_resp, down_resp, down_resp_size));

    // 반환된 CMHF 정보 확인
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, app_cmhf_name, strlen(app_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, app_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, app_cmhf, app_cmhf_size));
    free(res.common.cmhf_name);
    free(res.common.cmhf);

    // 반환된 옵션정보 확인
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.dir_name, down_dirname, strlen(down_dirname)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert_filename, app_cert_filename, strlen(app_cert_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key_filename, priv_key_filename, strlen(priv_key_filename)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv_filename, recon_priv_filename, strlen(recon_priv_filename)));
    ASSERT_EQ(res.options.cert.size, ac.size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.cert.octs, ac.octs, ac.size));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.priv_key.octs, priv_key.octs, sizeof(priv_key.octs)));
    ASSERT_TRUE(Dot2Test_CompareOctets(res.options.recon_priv.octs, recon_priv.octs, sizeof(recon_priv.octs)));

  }

  /*
   * 테스트 - return_options=false일 때의 동작을 확인한다.
   */
  {
    // 정상동작 확인
    params.return_options = false;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);

    // 실행 중에 저장된 테스트벡터 값이 정상인 것을 확인한다
    // 실행 중간 단계에서 생성된 정보의 유효성 확인 (최종단계에서의 확인이 어려운 경우를 위해)
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.app_cert.res.down_req_filename, req_filename, strlen(req_filename)));
    ASSERT_EQ(g_dot2_mib.lcm.test.app_cert.res.down_resp_size, down_resp_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.app_cert.res.down_resp, down_resp, down_resp_size));

    // 반환된 CMHF 정보 확인
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf_name, app_cmhf_name, strlen(app_cmhf_name)));
    ASSERT_EQ(res.common.cmhf_size, app_cmhf_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.common.cmhf, app_cmhf, app_cmhf_size));
    free(res.common.cmhf_name);
    free(res.common.cmhf);

    // 옵션정보가 반환되지 않은 것을 확인한다.
    ASSERT_EQ(res.options.dir_name[0], 0);
    ASSERT_EQ(res.options.cert_filename[0], 0);
    ASSERT_EQ(res.options.priv_key_filename[0], 0);
    ASSERT_EQ(res.options.recon_priv_filename[0], 0);
    ASSERT_EQ(res.options.cert.size, 0u);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_DownloadAppCert, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 널 파라미터 전달
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 잘못된 다운로드요청문 H8 값 -> 요청문의 유효성은 서버가 판단하므로 여기서는 실패 여부를 알 수 없다.
    params.common.req_h8[0]++;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    free(res.common.cmhf_name);
    free(res.common.cmhf);
    params.common.req_h8[0]--; // 원상복구

    // 잘못된 서명용 임시 개인키
    params.common.verify_priv_key.octs[0]++;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_OSSL_InvalidReconstructedKeyPair);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.common.verify_priv_key.octs[0]--; // 원상복구

    // 잘못된 인증서암호화용 개인키
    params.common.cert_enc_priv_key.octs[0]++;;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_DecryptCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.common.cert_enc_priv_key.octs[0]--; // 원상복구

    // 널 인증서다운로드 URL
    params.common.cert_dl_url = nullptr;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    params.common.cert_dl_url = (char *)cert_dl_url; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 LCM 설정
 */
TEST(Dot2_DownloadAppCert, INVALID_LCM_CONFIG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // LCM 정보 설정 없이 호출
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 일부 LCM 설정 후 호츨 -> 임시압축파일저장경로가 설정되지 않은 상태
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 임시압축파일저장경로를 잘못된 경로로 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, "/no/no"), kDot2Result_Success);
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_FILE_Access);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);

    // 모든 필요 LCM 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_tv_bluetech_zip_file_path), kDot2Result_Success);
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.common.cmhf_name);
    ASSERT_TRUE(res.common.cmhf);
    free(res.common.cmhf_name);
    free(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 등록인증서 CMHF가 등록되지 않음
 */
TEST(Dot2_DownloadAppCert, NO_ENROL_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 등록인증서 CMHF 등록없이 호출
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief PCA 인증서가 등록되지 않음
 */
TEST(Dot2_DownloadAppCert, NO_PCA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // PCA 인증서 등록없이 호출
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief RA 인증서가 등록되지 않음
 */
TEST(Dot2_DownloadAppCert, NO_RA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // RA 인증서 등록없이 호출
    params.return_options = true;
    memcpy(params.common.req_h8, prov_req_h8, 8);
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 다운로드응답문(ZIP 파일)
 */
TEST(Dot2_DownloadAppCert, INVALID_DOWN_ZIP_FILE)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

    // SCC 인증서 등록 - RA를 등록하지 않음
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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
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
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;

    // 테스트벡터 다운로드 ZIP파일의 길이를 실제와 다르게 설정한다.
    size_t orig_zipfile_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size--;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_FILE_Unzip);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_zipfile_size; // 원상복구

    // 다운로드 ZIP 파일 내 첫번째 다운로드응답문의 길이를 유효하지 않게 설정한다.
    // 최소길이보다 짧게 설정한다. 최대길이보다 크게는 설정할 수 없다(내부에서 테스트벡터값으로 복사하면서 오버플로우 발생)
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = true;
    size_t orig_size = g_dot2_mib.lcm.test.app_cert.tv.down_resp_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = kDot2SPDUSize_Min - 1;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_InvalidCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = orig_size; // 원상복구

    // 다운로드 ZIP 파일 내 첫번째 다운로드응답문의 길이를 실제와 다르게 설정한다.
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = true;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size--;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DecodeCertDownloadResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size++; // 원상복구

    // 다운로드 ZIP 파일 내 첫번째 다운로드응답문의 서명을 변조한다. (서명은 응답문의 마지막에 수납되어 있다)
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = true;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp[g_dot2_mib.lcm.test.app_cert.tv.down_resp_size - 1]++;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_SignatureVerificationFailed);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.app_cert.tv.down_resp[g_dot2_mib.lcm.test.app_cert.tv.down_resp_size - 1]--; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 응답문 수신 오류
 */
TEST(Dot2_DownloadAppCert, DOWN_RESP_MSG_RX_ERROR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2AppCertDownloadRequestParams params{};
  struct Dot2AppCertDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{}, ac{};
  Dot2ECPrivateKey init_priv_key{}, enc_priv_key{}, recon_priv{}, priv_key{};
  uint8_t lccf[kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size;
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  const char *ec_cmhf_name = g_tv_bluetech_ec_resp_enrol_cmhf_name;
  const char *req_filename = g_tv_bluetech_app_cert_down_req_filename;
  uint8_t zipfile[1000];
  size_t zipfile_size;
  const char *app_cmhf_name = g_tv_bluetech_app_cert_down_cmhf_name;
  uint8_t app_cmhf[kDot2CMHFSize_Max];
  size_t app_cmhf_size;
  const char *down_dirname = g_tv_bluetech_app_cert_down_dir_name;
  const char *app_cert_filename = g_tv_bluetech_app_cert_down_cert_filename;
  const char *priv_key_filename = g_tv_bluetech_app_cert_down_priv_key_filename;
  const char *recon_priv_filename = g_tv_bluetech_app_cert_down_recon_priv_filename;
  uint8_t prov_req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_app_cert_prov_resp_cert_dl_url;
  uint8_t down_resp[500];
  size_t down_resp_size;

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
    ASSERT_EQ(lccf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_lccf, lccf), g_tv_bluetech_ec_resp_lccf_size);
    ASSERT_EQ(ec_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_ec_resp_enrol_cmhf, ec_cmhf), g_tv_bluetech_ec_resp_enrol_cmhf_size);
    ASSERT_EQ(zipfile_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_zipfile, zipfile), g_tv_bluetech_app_cert_down_zipfile_size);
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_cmhf, app_cmhf), g_tv_bluetech_app_cert_down_cmhf_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_prov_req_h8, prov_req_h8), 8);
    ASSERT_EQ(down_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_app_cert_down_resp.resp, down_resp), g_tv_bluetech_app_cert_down_resp.resp_size);

    // SCC 인증서 등록 - RA를 등록하지 않음
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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, zipfile, zipfile_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = zipfile_size;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_replace = false;
    g_dot2_mib.lcm.test.app_cert.tv.down_resp_size = down_resp_size;
    memcpy(g_dot2_mib.lcm.test.app_cert.tv.down_resp, down_resp, down_resp_size);
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
    memcpy(&params.common.verify_priv_key, &init_priv_key, sizeof(init_priv_key));
    memcpy(&params.common.cert_enc_priv_key, &enc_priv_key, sizeof(enc_priv_key));
    params.common.cert_dl_url = (char *)cert_dl_url;

    // CURL 실행 결과를 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_UNSUPPORTED_PROTOCOL;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_curl_easy_perform);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK; // 원상복구

    // 수신되는 HTTP CODE 값을 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_NOT_MODIFIED;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoModifiedFile);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_DownloadInfoUnvailable);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_ServerError);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = 0;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK; // 원상복구

    // 수신되는 응답메시지의 길이를 0으로 강제설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_DownloadAppCert(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.common.cmhf_name);
    ASSERT_FALSE(res.common.cmhf);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구
  }

  Dot2_Release();
}
