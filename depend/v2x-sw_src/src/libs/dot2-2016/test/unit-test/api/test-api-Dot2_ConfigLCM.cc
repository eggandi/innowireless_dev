/**
 * @file
 * @brief Dot2_ConfigLCM() API 테스트
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
TEST(Dot2_ConfigLCM, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다
   */
  {
    // LPF 요청 URL 설정
    const char *lpf_req_url = g_tv_bluetech_lpf_req_url;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, lpf_req_url), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.ra.lpf_url, lpf_req_url, strlen(lpf_req_url)));

    // LCCF 요청 URL 설정
    const char *lccf_req_url = g_tv_bluetech_lccf_req_url;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LCCFReqURL, lccf_req_url), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.ra.lccf_url, lccf_req_url, strlen(lccf_req_url)));

    // CRL 요청 URL 설정
    const char *crl_req_url = g_tv_bluetech_crl_req_url;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_CRLReqURL, crl_req_url), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.ra.crl_url, crl_req_url, strlen(crl_req_url)));

    // 응용인증서 발급요청 URL 설정
    const char *app_cert_req_url = g_tv_bluetech_app_cert_req_url;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_AppCertProvisioningReqURL, app_cert_req_url), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.ra.acp_url, app_cert_req_url, strlen(app_cert_req_url)));

    // 익명인증서 발급요청 URL 설정
    const char *pseudonym_cert_req_url = g_tv_bluetech_pseudonym_cert_req_url;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_PseudonymCertProvisioningReqURL, pseudonym_cert_req_url), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.ra.pcp_url, pseudonym_cert_req_url, strlen(pseudonym_cert_req_url)));

    // 식별인증서 발급요청 URL 설정
    const char *id_cert_req_url = g_tv_bluetech_id_cert_req_url;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_IdCertProvisioningReqURL, id_cert_req_url), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.ra.icp_url, id_cert_req_url, strlen(id_cert_req_url)));

    // RCA TLS 인증서 경로 설정
    const char *rca_tls_cert_path = g_tv_bluetech_rca_tls_cert_path;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, rca_tls_cert_path), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.tls.rca_cert_file_path, rca_tls_cert_path, strlen(rca_tls_cert_path)));

    // 임시압축파일저장 경로 설정
    const char *zip_file_path = g_tv_bluetech_zip_file_path;
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, zip_file_path), kDot2Result_Success);
    ASSERT_TRUE(Dot2Test_CompareOctets(g_dot2_mib.lcm.tmp_zip_file_path, zip_file_path, strlen(zip_file_path)));
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_ConfigLCM, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
   * 테스트 : 유효하지 않은 파라미터에 대한 동작을 확인한다.
   */
  {
    // 널 파라미터
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, nullptr), -kDot2Result_NullParameters);

    // 유효하지 않은 설정 유형
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_Max + 1, g_tv_bluetech_zip_file_path), -kDot2Result_LCM_InvalidConfigType);
  }

  Dot2_Release();
}
