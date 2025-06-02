/** 
  * @file 
  * @brief CRL 다운로드 유틸리티 인증서 관련 구현
  * @date 2022-12-10
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>
#include <dirent.h>

// 유틸리티 헤더 파일
#include "crl-req.h"


/**
 * @brief SCC 인증서 파일들을 로딩한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CRL_REQ_LoadSCCCertFiles(void)
{
  printf("Load SCC cert files(RCA,ICA,PCA,RA)\n");

  /*
   * RCA 파일을 로딩한다.
   */
  printf("Load RCA cert file(%s)\n", g_cfg.rca_file);
  int ret = Dot2_LoadSCCCertFile(g_cfg.rca_file);
  if (ret < 0) {
    printf("Fail to load RCA cert file: %d\n", ret);
    return -1;
  }

  /*
   * ICA 파일을 로딩한다.
   */
  printf("Load ICA cert file(%s)\n", g_cfg.ica_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.ica_file);
  if (ret < 0) {
    printf("Fail to load ICA cert file: %d\n", ret);
    return -1;
  }

  /*
   * PCA 파일을 로딩한다.
   */
  printf("Load PCA cert file(%s)\n", g_cfg.pca_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.pca_file);
  if (ret < 0) {
    printf("Fail to load PCA cert file: %d\n", ret);
    return -1;
  }

  /*
   * RA 파일을 로딩한다.
   */
  printf("Load RA cert file(%s)\n", g_cfg.ra_file);
  ret = Dot2_LoadSCCCertFile(g_cfg.ra_file);
  if (ret < 0) {
    printf("Fail to load RA cert file: %d\n", ret);
    return -1;
  }

  /*
   * CRLG 인증서 파일을 로딩한다.
   */
  if (g_cfg.op == kCRLReqOperationType_Load) {
    printf("Load CRLG cert file(%s)\n", g_cfg.load.crlg_file);
    ret = Dot2_LoadSCCCertFile(g_cfg.load.crlg_file);
    if (ret < 0) {
      printf("Fail to load CRLG cert file: %d\n", ret);
      return -1;
    }
  }

  return 0;
}
