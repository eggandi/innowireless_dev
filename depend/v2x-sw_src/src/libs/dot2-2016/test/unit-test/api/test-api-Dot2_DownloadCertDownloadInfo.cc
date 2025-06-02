/**
  * @file
  * @brief Dot2_DownloadCertDownloadInfo() API 단위테스트
  * @date 2023-03-02
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
TEST(Dot2_DownloadCertDownloadInfo, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

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

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 정상동작 확인
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_EQ(res.cert_dl_time, cert_dl_time);

    // 실행 중에 저장된 테스트벡터 값이 정상인 것을 확인한다
    // 실행 중간 단계에서 생성된 정보의 유효성 확인 (최종단계에서의 확인이 어려운 경우를 위해)
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.test.down_info.res.req_filename, req_filename, strlen(req_filename)));
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_DownloadCertDownloadInfo, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

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

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // 널 파라미터 전달
    res = Dot2_DownloadCertDownloadInfo(nullptr);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);

    // 잘못된 다운로드요청문 H8 값 -> 요청문의 유효성은 서버가 판단하므로 여기서는 실패 여부를 알 수 없다.
    params.req_h8[0]++;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_EQ(res.cert_dl_time, cert_dl_time);
    params.req_h8[0]--; // 원상복구

    // 널 인증서다운로드 URL
    params.cert_dl_url = nullptr;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_NullParameters);
    params.cert_dl_url = (char *)cert_dl_url; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 LCM 설정
 */
TEST(Dot2_DownloadCertDownloadInfo, INVALID_LCM_CONFIG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

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
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // LCM 정보 설정 없이 호출
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);

    // LCM 정상 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_EQ(res.cert_dl_time, cert_dl_time);
  }

  Dot2_Release();
}


/**
 * @brief 등록인증서 CMHF가 등록되지 않음
 */
TEST(Dot2_DownloadCertDownloadInfo, NO_ENROL_CMHF)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

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

    // 등록인증서 CMHF 등록을 누락한다.

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // 등록인증서 CMHF 등록없이 호출
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);

    // 등록인증서 CMHF 등록 후 호출
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_EQ(res.cert_dl_time, cert_dl_time);
  }

  Dot2_Release();
}


/**
 * @brief PCA 인증서가 등록되지 않음
 */
TEST(Dot2_DownloadCertDownloadInfo, NO_PCA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

    // SCC 인증서 등록 - PCA 누락
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 4u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // PCA 인증서 등록없이 호출
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);

    // PCA 등록 후 호출
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_EQ(res.cert_dl_time, cert_dl_time);
  }

  Dot2_Release();
}


/**
 * @brief RA 인증서가 등록되지 않음
 */
TEST(Dot2_DownloadCertDownloadInfo, NO_RA_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

    // SCC 인증서 등록 - RA 누락
    ASSERT_EQ(Dot2_AddSCCCert(rca.octs, rca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica.octs, ica.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca.octs, pca.size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca.octs, eca.size), kDot2Result_Success);
    ASSERT_FALSE(g_dot2_mib.scc_cert_info_table.ra);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 4u);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // RA 인증서 등록없이 호출
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_NoSufficientCertRequestInfo);

    // PCA 등록 후 호출
    ASSERT_EQ(Dot2_AddSCCCert(ra.octs, ra.size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra);
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_EQ(res.cert_dl_time, cert_dl_time);
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 응답문
 */
TEST(Dot2_DownloadCertDownloadInfo, INVALID_DOWN_RESP_MSG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

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

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // 테스트벡터 응답문의 길이를 실제와 다르게 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 3;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_ASN1_DeocdeCertDownloadInfoResponse);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size; // 원상복구
  }

  Dot2_Release();
}


/**
 * @brief 응답문 수신 오류
 */
TEST(Dot2_DownloadCertDownloadInfo, DOWN_RESP_MSG_RX_ERROR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2CertDownloadInfoRequestParams params{};
  struct Dot2CertDownloadInfoDownloadResult res{};
  memset(&params, 0, sizeof(params));

  Dot2Cert ec{}, eca{}, ra{}, rca{}, crlg{}, ica{}, pca{};
  uint8_t ec_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize ec_cmhf_size;
  uint8_t req_h8[8];
  const char *cert_dl_url = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_url;
  Dot2Time32 cert_dl_time = g_tv_bluetech_pseudonym_cert_down_info_cert_dl_time;
  char req_filename[100] = {};
  uint8_t down_info_resp[10];
  size_t down_info_resp_size;

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

    // 테스트벡터 바이트열 변환
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_prov_req_h8, req_h8), 8);
    strcpy(req_filename, g_tv_bluetech_pseudonym_cert_down_info_req_filename);
    ASSERT_EQ(down_info_resp_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_pseudonym_cert_down_info_resp, down_info_resp), g_tv_bluetech_pseudonym_cert_down_info_resp_size);

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

    // 등록인증서 CMHF 등록
    ASSERT_EQ(Dot2_LoadCMHF(ec_cmhf, ec_cmhf_size), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, down_info_resp, down_info_resp_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = down_info_resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 파라미터 설정
    memcpy(params.req_h8, req_h8, 8);
    params.cert_dl_url = (char *)cert_dl_url;

    // CURL 실행 결과를 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_UNSUPPORTED_PROTOCOL;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_curl_easy_perform);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK; // 원상복구

    // 수신되는 HTTP CODE 값을 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_NOT_MODIFIED;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoModifiedFile);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_DownloadInfoUnvailable);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_ServerError);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = 0;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK; // 원상복구

    // 수신되는 응답메시지의 길이를 0으로 강제설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_DownloadCertDownloadInfo(&params);
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구
  }

  Dot2_Release();
}
