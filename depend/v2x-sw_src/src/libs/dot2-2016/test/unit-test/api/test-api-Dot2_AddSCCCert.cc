/** 
  * @file 
  * @brief Dot2_AddSCCCert() API 단위 테스트
  * @date 2022-07-03 
  * @author gyun 
  */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief Dot2_AddSCCCert() API의 기본 동작을 확인한다.
 */
TEST(API_Dot2_AddSCCCert, NORMAL)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t rca_cert[kDot2CertSize_Max], ica_cert[kDot2CertSize_Max], pca_cert[kDot2CertSize_Max];
  uint8_t eca_cert[kDot2CertSize_Max], ra_cert[kDot2CertSize_Max];
  size_t rca_cert_size, ica_cert_size, pca_cert_size, eca_cert_size, ra_cert_size;

  /*
   * 준비 : RCA/ICA/PCA/ECA 인증서 정보 설정
   */
  {
    // 테스트벡터 RCA 인증서 바이트열 변환
    rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
    // 테스트벡터 ICA 인증서 바이트열 변환
    ica_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ica_cert, ica_cert);
    ASSERT_EQ(ica_cert_size, g_tv_ica_cert_size);
    // 테스트벡터 PCA 인증서 바이트열 변환
    pca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_pca_cert, pca_cert);
    ASSERT_EQ(pca_cert_size, g_tv_pca_cert_size);
    // 테스트벡터 ECA 인증서 바이트열 변환
    eca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_eca_cert, eca_cert);
    ASSERT_EQ(eca_cert_size, g_tv_eca_cert_size);
    // 테스트벡터 RA 인증서 바이트열 변환
    ra_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_ra_cert, ra_cert);
    ASSERT_EQ(ra_cert_size, g_tv_ra_cert_size);
  }

  /*
   * 테스트 : RCA/ICA/PCA/ECA/RA 인증서 저장 시 정상적으로 저장되는 것을 확인한다.
   */
  {
    ASSERT_EQ(Dot2_AddSCCCert(rca_cert, rca_cert_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica_cert, ica_cert_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca_cert, pca_cert_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca_cert, eca_cert_size), kDot2Result_Success);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra == nullptr);
    ASSERT_EQ(Dot2_AddSCCCert(ra_cert, ra_cert_size), kDot2Result_Success);
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 5u);
    ASSERT_TRUE(g_dot2_mib.scc_cert_info_table.ra != nullptr);
  }

  Dot2_Release();
}


/**
 * @brief 잘못된 파라미터 입력시의 동작을 확인한다.
 */
TEST(API_Dot2_AddSCCCert, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t rca_cert[kDot2CertSize_Max];
  size_t rca_cert_size;

  /*
   * 준비 : RCA 인증서 정보 설정
   */
  {
    // 테스트벡터 RCA 인증서 바이트열 변환
    rca_cert_size = (size_t)Dot2Test_ConvertHexStrToOctets(g_tv_rca_cert, rca_cert);
    ASSERT_EQ(rca_cert_size, g_tv_rca_cert_size);
  }

  /*
   * 테스트 : cert = NULL 전달 시 실패하는 것을 확인한다.
   */
  ASSERT_EQ(Dot2_AddSCCCert(nullptr, rca_cert_size), -kDot2Result_NullParameters);
  ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);

  /*
   * 테스트 : 내용이 유효하지 않은 cert 전달 시 실패하는 것을 확인한다.
   * - 내용이 맞지 않아 ASN.1 디코딩 실패
   */
  {
    const char *invalid_cert = "FFFF00809d195826018fbb3855811172612e73";
    uint8_t cert[kDot2CertSize_Max];
    size_t cert_size = Dot2Test_ConvertHexStrToOctets(invalid_cert, cert);
    ASSERT_EQ(Dot2_AddSCCCert(cert, cert_size), -kDot2Result_ASN1_DecodeCertificate);
  }

  /*
   * 테스트 : 유효하지 않은 cert_size 전달 시 실패하는 것을 확인한다.
   */
  {
    ASSERT_EQ(Dot2_AddSCCCert(rca_cert, kDot2CertSize_Max+1), -kDot2Result_CERT_InvalidCertSize); // 길이 조건 체크 실패
    ASSERT_EQ(Dot2_AddSCCCert(rca_cert, kDot2CertSize_Min-1), -kDot2Result_CERT_InvalidCertSize); // 길이 조건 체크 실패
    ASSERT_EQ(Dot2_AddSCCCert(rca_cert, rca_cert_size-1), -kDot2Result_ASN1_DecodeCertificate); // 길이 조건은 통과하였으나 데이터가 짧아 디코딩 실패
    ASSERT_EQ(Dot2_AddSCCCert(rca_cert, rca_cert_size+1), -kDot2Result_SignatureVerificationFailed); // 디코딩까지 성공하지만 해시값이 달라져 서명검증 실패
    ASSERT_EQ(g_dot2_mib.scc_cert_info_table.scc.entry_num, 0u);
  }

  Dot2_Release();
}
