/** 
  * @file 
  * @brief Rotate CMHF 로딩 관련 테스트
  * @date 2022-08-05 
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
TEST(LOAD_ROTATE_CMHF, CERT_BUNDLE_0)
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
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_rca, rca), (int)g_tv_bundle_0_rca_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_ica, ica), (int)g_tv_bundle_0_ica_size);
    ASSERT_EQ(Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pca, pca), (int)g_tv_bundle_0_pca_size);
    ASSERT_EQ(Dot2_AddSCCCert(rca, g_tv_bundle_0_rca_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(ica, g_tv_bundle_0_ica_size), kDot2Result_Success);
    ASSERT_EQ(Dot2_AddSCCCert(pca, g_tv_bundle_0_pca_size), kDot2Result_Success);
  }

  /*
   * 테스트 - g_tv_bundle_0_pseudonym_13a
   */
  {
    // 준비
    {
      // 테스트벡터를 바이트열로 변환
      ASSERT_EQ(cmhf_size = Dot2Test_ConvertHexStrToOctets(g_tv_bundle_0_pseudonym_13a_cmhf, cmhf), g_tv_bundle_0_pseudonym_13a_cmhf_size);
    }

    // CMHF 로딩 시 CMH에 저장된 정보가 정상인지 확인한다.
    {
      ASSERT_EQ(dot2_LoadCMHF(cmhf, cmhf_size), kDot2Result_Success);
      struct Dot2RotateCMHSetEntry *cmh_set_entry = TAILQ_FIRST(&(g_dot2_mib.cmh_table.pseudonym_id.head));
      ASSERT_TRUE(cmh_set_entry);
      ASSERT_EQ(g_dot2_mib.cmh_table.pseudonym_id.entry_num, 1U);
      ASSERT_FALSE(g_dot2_mib.cmh_table.pseudonym_id.active_set);
      ASSERT_EQ(g_dot2_mib.cmh_table.cmh_type, kDot2CMHType_Pseudonym);
      ASSERT_TRUE(Dot2Test_Check_CertBundle_0_PseudonymCert_13a_CMHSetEntry(cmh_set_entry));
    }
    // CMH 삭제
    dot2_ReleaseRotateCMHSetList(&(g_dot2_mib.cmh_table.pseudonym_id));
  }

  Dot2_Release();
}

