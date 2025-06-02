/**
  * @file
  * @brief CRL 로드 유틸리티 인증서 관련 구현
  * @date 2023-01-29
  * @author gyun
  */


// 시스템 헤더 파일
#include <stdio.h>
#include <dirent.h>

// 유틸리티 헤더 파일
#include "crl-req.h"


/**
 * @brief CRL 파일을 로딩한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CRL_REQ_LoadCRLFile(void)
{
  /*
   * CRL 파일을 로딩한다.
   */
  int ret = Dot2_LoadCRLFile(g_cfg.crl_file);
  if (ret < 0) {
    printf("Fail to Dot2_LoadCRLFile() : %d\n", ret);
    return -1;
  }

  printf("Success to load CRL file\n");
  return 0;
}
