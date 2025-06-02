/** 
  * @file 
  * @brief Sequential CMHF 로딩 관련 테스트
  * @date 2022-08-01 
  * @author gyun 
  */


// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

// 테스트 헤더 파일
#include "gtest/gtest.h"
#include "../../test-common-funcs/test-common-funcs.h"
#include "../../test-vectors/test-vectors.h"
#include "certificate/cert-info/dot2-cert-info.h"


/*
 * 인증서 번들 0 이용 테스트
 */
TEST(LOAD_SEQ_CMHF, CERT_BUNDLE_0)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t rca[kDot2CertSize_Max], ica[kDot2CertSize_Max], pca[kDot2CertSize_Max];
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;
  struct Dot2SequentialCMHEntry *cmh_entry[2] = { nullptr, nullptr };

  /*
   * 준비
   */
  {
    // 상위인증서들을 추가
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_rca, rca), (int)g_tv_bundle_0_rca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_ica, ica), (int)g_tv_bundle_0_ica_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, pca), (int)g_tv_bundle_0_pca_size);
    ASSERT_EQ(Dot2_AddSCCCert(rca, g_tv_bundle_0_rca_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica, g_tv_bundle_0_ica_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca, g_tv_bundle_0_pca_size), kDot2Result_Success);
  }

  /*
   * 테스트 - g_tv_bundle_0_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_0_cmhf, cmhf), g_tv_bundle_0_app_cert_0_cmhf_size);
    }

    // CMHF 로딩 시 CMH에 저장된 정보가 정상인지 확인한다.
    {
      ASSERT_EQ(dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
      cmh_entry[0] = TAILQ_FIRST(&(g_dot2_mib.cmh_table.app.head));
      ASSERT_TRUE(cmh_entry[0]);
      ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1U);
      ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
      ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
      ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_0_CMHEntry(cmh_entry[0]));
    }
  }

  /*
   * 테스트 - g_tv_bundle_0_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_app_cert_1_cmhf, cmhf), g_tv_bundle_0_app_cert_1_cmhf_size);
    }

    // CMHF 로딩 시 CMH에 저장된 정보가 정상인지 확인한다.
    {
      ASSERT_EQ(dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
      cmh_entry[1] = TAILQ_NEXT(cmh_entry[0], entries);
      ASSERT_TRUE(cmh_entry[1]);
      ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 2U);
      ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
      ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
      ASSERT_TRUE(Dot2Test_Check_CertBundle_0_AppCert_1_CMHEntry(cmh_entry[1]));
    }
  }

  Dot2_Release();
}


/*
 * 인증서 번들 1 이용 테스트
 */
TEST(LOAD_SEQ_CMHF, CERT_BUNDLE_1)
{
  ASSERT_EQ(Dot2_Init(kDot2LogLevel_Err, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default), kDot2Result_Success);

  uint8_t rca[kDot2CertSize_Max], ica[kDot2CertSize_Max], pca[kDot2CertSize_Max], eca[kDot2CertSize_Max];
  uint8_t cmhf[kDot2CMHFSize_Max];
  Dot2CMHFSize cmhf_size;

  /*
   * 준비
   */
  {
    // 상위인증서들을 추가
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_rca, rca), g_tv_bundle_1_rca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_ica, ica), g_tv_bundle_1_ica_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_pca, pca), g_tv_bundle_1_pca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_eca, eca), g_tv_bundle_1_eca_size);
    ASSERT_EQ(Dot2_AddSCCCert(rca, g_tv_bundle_1_rca_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica, g_tv_bundle_1_ica_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca, g_tv_bundle_1_pca_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(eca, g_tv_bundle_1_eca_size), kDot2Result_Success);
  }

  /*
   * 테스트 - g_tv_bundle_1_enrol_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_enrol_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_1_enrol_cert_0_cmhf_size);
    }

    // CMHF 로딩 시 CMH에 저장된 정보가 정상인지 확인한다.
    {
      ASSERT_EQ(dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
      struct Dot2SequentialCMHEntry *cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.enrol.head));
      ASSERT_TRUE(cmh_entry);
      ASSERT_EQ(g_dot2_mib.cmh_table.enrol.entry_num, 1U);
      ASSERT_FALSE(g_dot2_mib.cmh_table.enrol.active_cmh);;
      ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Undefined);
      ASSERT_TRUE(Dot2Test_Check_CertBundle_1_EnrolCert_0_CMHEntry(cmh_entry));
    }
    // CMH 삭제
    dot2_ReleaseSequentialCMHList(&(g_dot2_mib.cmh_table.enrol));
  }

  /*
   * 테스트 - g_tv_bundle_1_app_cert_0
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_0_cmhf, cmhf), (size_t)g_tv_bundle_1_app_cert_0_cmhf_size);
    }

    // CMHF 로딩 시 CMH에 저장된 정보가 정상인지 확인한다.
    {
      ASSERT_EQ(dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
      struct Dot2SequentialCMHEntry *cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.app.head));
      ASSERT_TRUE(cmh_entry);
      ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1U);
      ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
      ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
      ASSERT_TRUE(Dot2Test_Check_CertBundle_1_AppCert_0_CMHEntry(cmh_entry));
    }
    // CMH 삭제
    dot2_ReleaseSequentialCMHList(&(g_dot2_mib.cmh_table.app));
  }

  /*
   * 테스트 - g_tv_bundle_1_app_cert_1
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_1_app_cert_1_cmhf, cmhf), (size_t)g_tv_bundle_1_app_cert_1_cmhf_size);
    }

    // CMHF 로딩 시 CMH에 저장된 정보가 정상인지 확인한다.
    {
      ASSERT_EQ(dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
      struct Dot2SequentialCMHEntry *cmh_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.app.head));
      ASSERT_TRUE(cmh_entry);
      ASSERT_EQ(g_dot2_mib.cmh_table.app.entry_num, 1U);
      ASSERT_FALSE(g_dot2_mib.cmh_table.app.active_cmh);;
      ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Application);
      ASSERT_TRUE(Dot2Test_Check_CertBundle_1_AppCert_1_CMHEntry(cmh_entry));
    }
    // CMH 삭제
    dot2_ReleaseSequentialCMHList(&(g_dot2_mib.cmh_table.app));
  }

  Dot2_Release();
}
