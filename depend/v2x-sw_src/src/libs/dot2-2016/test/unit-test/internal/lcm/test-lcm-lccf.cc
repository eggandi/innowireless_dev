/**
  * @file
  * @brief LCCF 기능에 대한 단위 테스트
  * @date 2022-06-30
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-vectors/test-vectors.h"
#include "../../test-common-funcs/test-common-funcs.h"


/**
 * @brief LCCF 처리 기능이 정상적으로 동작하는 것을 확인한다.
 */
TEST(PARSE_LCCF, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t lccf[2][kDot2LCCFSize_Max];
  Dot2LCCFSize lccf_size[2];
  int ret;

  /*
   * 준비 - 기대값 설정
   */
  {
    // 테스트벡터 LCCF 바이트열 변환
    ASSERT_EQ(lccf_size[0] = Dot2Test_ConvertHexStrToOctets(g_tv_ssotech_lccf_1, lccf[0]), g_tv_ssotech_lccf_1_size);
    ASSERT_EQ(lccf_size[1] = Dot2Test_ConvertHexStrToOctets(g_tv_crosscert_lccf_1, lccf[1]), g_tv_crosscert_lccf_1_size);
  }

  /*
   * 테스트 - LCCF#1가 정상적으로 파싱되는 것을 확인한다.
   */
  {
    uint8_t *rca_cert = nullptr, *ica_cert = nullptr, *pca_cert = nullptr, *crlg_cert = nullptr;
    Dot2CertSize rca_cert_size, ica_cert_size, pca_cert_size, crlg_cert_size;
#if defined(_FFASN1C_)
    ret = dot2_ffasn1c_ParseLCCF(lccf[0],
                                 lccf_size[0],
                                 &rca_cert,
                                 &rca_cert_size,
                                 &ica_cert,
                                 &ica_cert_size,
                                 &pca_cert,
                                 &pca_cert_size,
                                 &crlg_cert,
                                 &crlg_cert_size);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_FALSE(rca_cert); // 본 테스트벡터에는 RCA 인증서가 포함되어 있지 않다.
    ASSERT_TRUE(ica_cert);
    ASSERT_TRUE(pca_cert);
    ASSERT_FALSE(crlg_cert); // 본 테스트벡터에는 CRLG 인증서가 포함되어 있지 않다.
#endif
  }

  /*
   * 테스트 - LCCF#2가 정상적으로 파싱되는 것을 확인한다.
   */
  {
    uint8_t *rca_cert = nullptr, *ica_cert = nullptr, *pca_cert = nullptr, *crlg_cert = nullptr;
    Dot2CertSize rca_cert_size, ica_cert_size, pca_cert_size, crlg_cert_size;
#if defined(_FFASN1C_)
    ret = dot2_ffasn1c_ParseLCCF(lccf[1],
                                 lccf_size[1],
                                 &rca_cert,
                                 &rca_cert_size,
                                 &ica_cert,
                                 &ica_cert_size,
                                 &pca_cert,
                                 &pca_cert_size,
                                 &crlg_cert,
                                 &crlg_cert_size);
    ASSERT_EQ(ret, kDot2Result_Success);
    ASSERT_TRUE(rca_cert);
    ASSERT_TRUE(ica_cert);
    ASSERT_TRUE(pca_cert);
    ASSERT_FALSE(crlg_cert); // 본 테스트벡터에는 CRLG 인증서가 포함되어 있지 않다.
#endif
  }

  Dot2_Release();
}
