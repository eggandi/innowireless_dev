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
 * @brief CRL을 다운로드한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CRL_REQ_DownloadCRL(void)
{
  struct Dot2CRLDownloadResult res;

  /*
   * 인증서 다운로드를 수행한다.
   */
  res = Dot2_DownloadCRL();
  if (res.ret < 0) {
    printf("Fail to Dot2_DownloadCRL() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  CRL_REQ_PrintOcts("CRL", res.crl, res.crl_size);

  /*
   * CRL을 파일에 저장한다.
   */
  int ret = CRL_REQ_ExportFile(g_cfg.crl_file, res.crl, res.crl_size);

  free(res.crl);
  return ret;
}
