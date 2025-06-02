/** 
 * @file
 * @brief Dot2_LoadCMHFFile() API에 대한 단위테스트 구현 파일
 * @date 2021-04-08
 * @author gyun
 *
 * 본 단위테스트를 수행하기 위해 단위테스트 실행파일이 위치한 디렉토리로부터의 상대경로인 test/test-file/certificates/ 디렉토리에
 * 각 번들(test-vector-cert-bundle-*.c)에 대한 cmhf2 파일들이 존재한다.
 * 또한
 * 유효하지 않은 CMHF 파일에 대한 예외 처리를 잘 수행하는 것을 확인하기 위해 test/sample/certificate 디렉토리에
 * 일부러 잘못된 파일들(abnormal.cmhf, abnormal-long.cmhf, abnormal-short.cmhf)을 포함시켜 테스트한다.
 */


// 라이브러리 헤더 파일
#include "dot2/dot2.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-common-funcs/test-common-funcs.h"
#include "../test-vectors/test-vectors.h"


/**
 * @brief 어플리케이션 인증서 CMHF 파일 로딩 테스트
 */
TEST(Dot2_LoadCMHFFile, APP_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SequentialCMHEntry *cmh_entry = nullptr;

  /*
   * 준비
   */
  {
    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_0_SCCCerts();
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/a_135_210107.133529-210211.233529_key.cmhf2"), kDot2Result_Success);

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
 * @brief 익명 인증서 CMHF 파일 로딩 테스트
 */
TEST(Dot2_LoadCMHFFile, PSEUDONYM_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2RotateCMHSetEntry *cmh_entry = nullptr;

  /*
   * 준비
   */
  {
    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_0_SCCCerts();
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/p_32_38_210112.085958-210119.095958_key.cmhf2"), kDot2Result_Success);

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
 * @brief 식별 인증서 CMHF 파일 로딩 테스트
 */
TEST(Dot2_LoadCMHFFile, ID_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2RotateCMHSetEntry *cmh_entry = nullptr;

  /*
   * 준비
   */
  {
    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_1_SCCCerts();
  }

  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-1/i_32_35_135_150106.085958-150113.095958_key.cmhf2"), kDot2Result_Success);

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
 * @brief 등록 인증서 CMHF 파일 로딩 테스트
 */
TEST(Dot2_LoadCMHFFile, ENROL_CERT)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  struct Dot2SequentialCMHEntry *cmh_entry = nullptr;

  /*
   * 준비
   */
  {
    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_1_SCCCerts();
  }


  /*
   * 테스트 : API가 정상 동작하는 것을 확인한다 - 로딩된 첫번째 CMH 확인
   */
  {
    // API 호출
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-1/e_32_35_135_220802.122920-280731.122920_key.cmhf2"), kDot2Result_Success);

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
TEST(Dot2_LoadCMHFFile, INVALID_PARAMS)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  /*
   * 준비
   */
  {
    // SCC인증서(rca, ica, eca, pca, ra) 추가
    Dot2Test_Add_CertBundle_0_SCCCerts();
  }

  /*
   * 테스트 : 유효하지 않은 파라미터 대한 동작을 확인한다.
   */
  {
    // 널 파라미터
    ASSERT_EQ(Dot2_LoadCMHFFile(nullptr), -kDot2Result_NullParameters);
    // 존재하지 않는 파일
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/1.cmhf2"), -kDot2Result_FILE_Access);
    // 디렉토리
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0"), -kDot2Result_FILE_Access);
    // 변경된(변조된) 파일
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/altered.cmhf2"), -kDot2Result_CMHF_InvalidH8);
    // 너무 짧은 파일
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/shorter-than-min.cmhf2"), -kDot2Result_FILE_InvalidLength);
    ASSERT_TRUE(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/shorter-than-real.cmhf2") < 0);
    // 너무 긴 파일
    ASSERT_EQ(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/longer-than-max.cmhf2"), -kDot2Result_FILE_InvalidLength);
    ASSERT_TRUE(Dot2_LoadCMHFFile("test/test-file/certificates/bundle-0/longer-than-real.cmhf2") < 0);
  }

  Dot2_Release();
}
