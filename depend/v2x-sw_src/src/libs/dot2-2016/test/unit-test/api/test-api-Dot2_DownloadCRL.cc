/**
  * @file
  * @brief Dot2_DownloadCRL() API 단위테스트
  * @date 2023-03-03
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
TEST(Dot2_DownloadCRL, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  struct Dot2CRLDownloadResult res{};

  uint8_t crl[200];
  Dot2CRLSize crl_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lv_crl_down, crl), g_tv_bluetech_lv_crl_down_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_CRLReqURL, g_tv_bluetech_crl_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, crl, crl_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = crl_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // 정상동작 확인
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.crl);
    ASSERT_EQ(res.crl_size, crl_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.crl, crl, crl_size));
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 LCM 설정
 */
TEST(Dot2_DownloadCRL, INVALID_LCM_CONFIG)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  struct Dot2CRLDownloadResult res{};

  uint8_t crl[200];
  Dot2CRLSize crl_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lv_crl_down, crl), g_tv_bluetech_lv_crl_down_size);

    // LCM 설정을 누락한다.

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, crl, crl_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = crl_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // LCM 정보 설정 없이 호출
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.crl);

    // 일부 LCM 설정 후 호츨 -> RCA TLS 인증서 경로가 설정되지 않은 상태
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_CRLReqURL, g_tv_bluetech_crl_req_url), kDot2Result_Success);
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoConnectionInfo);
    ASSERT_FALSE(res.crl);

    // 모든 필요 LCM 설정 후 호출
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, kDot2Result_Success);
    ASSERT_TRUE(res.crl);
    ASSERT_EQ(res.crl_size, crl_size);
    ASSERT_TRUE(Dot2Test_CompareOctets(res.crl, crl, crl_size));
  }

  Dot2_Release();
}



/**
 * @brief 응답문 수신 오류
 */
TEST(Dot2_DownloadCRL, DOWN_RESP_MSG_RX_ERROR)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);
  struct Dot2CRLDownloadResult res{};

  uint8_t crl[200];
  Dot2CRLSize crl_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(crl_size = Dot2Test_ConvertHexStrToOctets(g_tv_bluetech_lv_crl_down, crl), g_tv_bluetech_lv_crl_down_size);

    // LCM 설정
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_CRLReqURL, g_tv_bluetech_crl_req_url), kDot2Result_Success);
    ASSERT_EQ(Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_tv_bluetech_rca_tls_cert_path), kDot2Result_Success);

    // 라이브러리 내부 테스트벡터 설정
    memcpy(g_dot2_mib.lcm.test.https_resp_tv.resp, crl, crl_size);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = crl_size;
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK;
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK;
  }

  /*
   * 테스트
   */
  {
    // CURL 실행 결과를 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_UNSUPPORTED_PROTOCOL;
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_curl_easy_perform);
    ASSERT_FALSE(res.crl);
    g_dot2_mib.lcm.test.https_resp_tv.res = CURLE_OK; // 원상복구

    // 수신되는 HTTP CODE 값을 실패로 강제 설정한다.
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_NOT_MODIFIED;
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_NoModifiedFile);
    ASSERT_FALSE(res.crl);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE;
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_DownloadInfoUnvailable);
    ASSERT_FALSE(res.crl);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR;
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_ServerError);
    ASSERT_FALSE(res.crl);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = 0;
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.crl);
    g_dot2_mib.lcm.test.https_resp_tv.http_code = DOT2_HTTPS_CODE_OK; // 원상복구

    // 수신되는 응답메시지의 길이를 0으로 강제설정한다.
    size_t orig_resp_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size;
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = 0;
    res = Dot2_DownloadCRL();
    ASSERT_EQ(res.ret, -kDot2Result_LCM_HTTPS_InvalidResponse);
    ASSERT_FALSE(res.crl);
    g_dot2_mib.lcm.test.https_resp_tv.resp_size = orig_resp_size; // 원상복구
  }

  Dot2_Release();
}
