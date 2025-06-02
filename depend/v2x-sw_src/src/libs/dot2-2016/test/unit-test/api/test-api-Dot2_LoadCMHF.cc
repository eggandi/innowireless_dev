/**
 * @file
 * @brief Dot2_LoadCMHF() API 테스트
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
 * @brief 어플리케이션 인증서 CMHF 로딩 테스트
 */
TEST(Dot2_LoadCMHF, APP_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SequentialCMHEntry *cmh_entry = nullptr;
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);

    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_0_SCCCerts();
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);

    // 결과 확인
    ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1u);
    ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 0u);
    ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 0u);
    ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
    ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
    cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.app.head));
    ASSERT_TRUE(cmh_entry);
    ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_0_CMHEntry(cmh_entry));
  }

  Dot2_Release();
}


/**
 * @brief 익명 인증서 CMHF 로딩 테스트
 */
TEST(Dot2_LoadCMHF, PSEUDONYM_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2RotateCMHSetEntry *cmh_entry = nullptr;
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_cmhf, cmhf), (size_t)g_tv_bundle_0_pseudonym_13a_cmhf_size);

    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_0_SCCCerts();
  }


  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);

    // 결과 확인
    ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 0u);
    ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1u);
    ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 0u);
    ASSERT_FALSE(g_dot2_mib.cmh_table.pseudonym_id.active_set);;
    ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Pseudonym);
    cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.pseudonym_id.head));
    ASSERT_TRUE(cmh_entry);
    ASSERT_TRUE(Dot2Test_Check_CertBundle_0_PseudonymCert_13a_CMHSetEntry(cmh_entry));
  }

  Dot2_Release();
}


/**
 * @brief 식별 인증서 CMHF 로딩 테스트
 */
TEST(Dot2_LoadCMHF, ID_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2RotateCMHSetEntry *cmh_entry = nullptr;
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_1_id_cert_0_cmhf_size);

    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_1_SCCCerts();
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);

    // 결과 확인
    ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 0u);
    ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1u);
    ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 0u);
    ASSERT_FALSE(g_dot2_mib.cmh_table.pseudonym_id.active_set);;
    ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Identification);
    cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.pseudonym_id.head));
    ASSERT_TRUE(cmh_entry);
    ASSERT_TRUE(Dot2Test_Check_CertBundle_1_IdCert_0_CMHSetEntry(cmh_entry));
  }

  Dot2_Release();
}


/**
 * @brief 등록 인증서 CMHF 로딩 테스트
 */
TEST(Dot2_LoadCMHF, ENROL_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SequentialCMHEntry *cmh_entry = nullptr;
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_1_enrol_cert_0_cmhf_size);

    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_1_SCCCerts();
  }


  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);

    // 결과 확인
    ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 0u);
    ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 0u);
    ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1u);
    ASSERT_FALSE(g_dot2_mib.cmh_table.enrol.active_cmh);;
    cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.enrol.head));
    ASSERT_TRUE(cmh_entry);
    ASSERT_TRUE(Dot2Test_Check_CertBundle_1_EnrolCert_0_CMHEntry(cmh_entry));
  }

  Dot2_Release();
}


/**
 * @brief 유효하지 않은 파라미터 테스트
 */
TEST(Dot2_LoadCMHF, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);

    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_0_SCCCerts();
  }


  /*
   * 테스트 : 유효하지 않은 파라미터에 대한 동작을 확인한다.
   */
  {
    // 널 파라미터
    ASSERT_EQ(Dot2_LoadCMHF(nullptr, cmhf_size), -kDot2Result_NullParameters);
    // 잘못된 cmhf 길이
    ASSERT_TRUE(Dot2_LoadCMHF(cmhf, cmhf_size - 1) < 0);
    ASSERT_TRUE(Dot2_LoadCMHF(cmhf, cmhf_size + 1) < 0);
    // 유효하지 않은 cmhf 길이
    ASSERT_EQ(Dot2_LoadCMHF(cmhf, kDot2CMHFSize_Min - 1), -kDot2Result_CMHF_InvalidSize);
    for (unsigned int i = kDot2CMHFSize_Min; i <= kDot2CMHFSize_Max; i++) {
      if (i != cmhf_size) {
        ASSERT_TRUE(Dot2_LoadCMHF(cmhf, i) < 0);
      }
    }
    ASSERT_EQ(Dot2_LoadCMHF(cmhf, kDot2CMHFSize_Max + 1), -kDot2Result_CMHF_InvalidSize);
  }

  Dot2_Release();
}


/**
 * @brief SCC 인증서 미등록
 */
TEST(Dot2_LoadCMHF, NO_SCC_CERTS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t app_cmhf[kDot2CMHFSize_Max], pseudonym_cmhf[kDot2CMHFSize_Max], id_cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize app_cmhf_size, pseudonym_cmhf_size, id_cmhf_size;

  /*
   * 준비
   */
  {
    // 테스트벡터 바이트열 변환
    ASSERT_EQ(app_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, app_cmhf), (size_t)g_tv_bundle_0_app_cert_0_cmhf_size);
    ASSERT_EQ(pseudonym_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_cmhf, pseudonym_cmhf), (size_t)g_tv_bundle_0_pseudonym_13a_cmhf_size);
    ASSERT_EQ(id_cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_id_cert_0_cmhf, id_cmhf), (size_t)g_tv_bundle_1_id_cert_0_cmhf_size);

    // SCC인증서(rca, ica, eca, pca, ra) 등록을 누락한다.
  }

  /*
   * 테스트
   */
  {
    ASSERT_EQ(Dot2_LoadCMHF(app_cmhf, app_cmhf_size), -kDot2Result_CMHF_NoIssuer);
    ASSERT_EQ(Dot2_LoadCMHF(pseudonym_cmhf, pseudonym_cmhf_size), -kDot2Result_CMHF_NoIssuer);
    ASSERT_EQ(Dot2_LoadCMHF(id_cmhf, id_cmhf_size), -kDot2Result_CMHF_NoIssuer);
  }

  Dot2_Release();
}
