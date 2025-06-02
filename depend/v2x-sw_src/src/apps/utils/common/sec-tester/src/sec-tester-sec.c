/** 
 * @file
 * @brief
 * @date 2020-10-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"

// 유틸리티 헤더 파일
#include "sec-tester.h"


/**
 * @brief 샘플 CA 인증서 정보들을 dot2 라이브러리에 로딩한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SEC_TESTER_LoadSampleCACerts(void)
{
  printf("Load sample CA certificates\n");

  /*
   * 샘플 SCC 인증서들을 등록한다.
   */
  int ret = Dot2_AddSCCCert(g_sample_rca_cert, g_sample_rca_cert_size);
  if (ret < 0) {
    printf("Fail to load sample RCA certificate - Dot2_AddSCCCert() failed: %d\n", ret);
    return -1;
  }
  ret = Dot2_AddSCCCert(g_sample_ica_cert, g_sample_ica_cert_size);
  if (ret < 0) {
    printf("Fail to load sample ICA certificate - Dot2_AddSCCCert() failed: %d\n", ret);
    return -1;
  }
  ret = Dot2_AddSCCCert(g_sample_pca_cert, g_sample_pca_cert_size);
  if (ret < 0) {
    printf("Fail to load sample PCA certificate - Dot2_AddSCCCert() failed: %d\n", ret);
    return -1;
  }

  printf("Sucess to load sample certificates\n");
  return 0;
}


/**
 * @brief 샘플 CMHF를 dot2 라이브러리에 로딩한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SEC_TESTER_LoadSampleCMHF(void)
{
  printf("Load sample CMHF\n");

  /*
   * 샘플 RSE 인증서 CMHF를 등록한다.
   */
  int ret = Dot2_LoadCMHF(g_sample_rse_0_cmhf2, g_sample_rse_0_cmhf2_size);
  if (ret < 0) {
    printf("Fail to load sample rse CMHF - Dot2_LoadCMHF() failed: %d\n", ret);
    return -1;
  }

  printf("Sucess to load sample CMHF\n");
  return 0;
}


/**
 * @brief 서명메시지 생성/처리를 위한 CMFH, 인증서정보, Security profile을 등록한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int SEC_TESTER_RegisterCryptoMaterials(void)
{
  int ret;
  printf("Register crypto materials\n");

  /*
   * 샘플 상위인증서(CA) 및 CMHF(RSE 인증서) 정보를 로딩한다.
   */
  ret = SEC_TESTER_LoadSampleCACerts();
  if (ret < 0) {
    return -1;
  }
  ret = SEC_TESTER_LoadSampleCMHF();
  if (ret < 0) {
    return -1;
  }

  /*
   * 테스트(rse-0 인증서로 서명가능한)용 Security profile을 등록한다
   * - 모든 체크를 모두 수행하도록 설정한다.
   */
  struct Dot2SecProfile profile;
  memset(&profile, 0, sizeof(profile));
  profile.psid = g_sample_rse_0_psid;
  profile.tx.gen_time_hdr = true;
  profile.tx.gen_location_hdr = true;
  profile.tx.exp_time_hdr = true;
  profile.tx.spdu_lifetime = 30 * 1000 * 1000;
  profile.tx.min_inter_cert_time = 495000ULL;
  profile.tx.sign_type = kDot2SecProfileSign_Compressed;
  profile.tx.ecp_format = kDot2SecProfileEcPointFormat_Compressed;
  profile.tx.interval = 100;
  profile.rx.verify_data = true;
  profile.rx.relevance_check.replay = false; // 동일한 SPDU에 대해 반복 테스트하므로 replay 체크는 비활성화한다.
  profile.rx.relevance_check.gen_time_in_past = g_relevance_consistency_check;
  profile.rx.relevance_check.validity_period = 10000ULL; // 10msec
  profile.rx.relevance_check.gen_time_in_future = g_relevance_consistency_check;
  profile.rx.relevance_check.acceptable_future_data_period = 60000000ULL; // 1분
  profile.rx.relevance_check.gen_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.exp_time = g_relevance_consistency_check;
  profile.rx.relevance_check.exp_time_src = kDot2RelevanceTimeSource_SecurityHeader;
  profile.rx.relevance_check.gen_location_distance = g_relevance_consistency_check;
  profile.rx.relevance_check.cert_expiry = g_relevance_consistency_check;
  profile.rx.consistency_check.gen_location = g_relevance_consistency_check;
  ret = Dot2_AddSecProfile(&profile);
  if (ret < 0) {
    printf("Fail to register crypto materials - Dot2_AddSecProfile() failed: %d\n", ret);
    return -1;
  }

  printf("Success to register crypto materials\n");
  return 0;
}


