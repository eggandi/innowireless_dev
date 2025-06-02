/** 
  * @file 
  * @brief LPF 다운로드 관련 구현
  * @date 2022-07-31 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "app-cert-req.h"


/**
 * @brief LPF를 다운로드한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int APP_CERT_REQ_DownloadLPF(void)
{
  char *current_filename = NULL;
  if (g_cfg.lpf.current_filename_present) {
    current_filename = g_cfg.lpf.current_filename;
  }

  struct Dot2LPFRequestResult res;
  res = Dot2_DownloadLPF(current_filename);
  if (res.ret == -kDot2Result_LCM_HTTPS_NoModifiedFile) {
    printf("LPF download result: No modified file in server, use current file\n");
    return 0;
  } else if (res.ret < 0) {
    printf("Fail to Dot2_DownloadLPF() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  printf("LPF filename: %s\n", res.lpf_filename);
  APP_CERT_REQ_PrintOcts("LPF", res.lpf, res.lpf_size);

  /*
   * 결과를 파일에 저장한다.
   */
  APP_CERT_REQ_ExportFile(res.lpf_filename, res.lpf, res.lpf_size);

  free(res.lpf_filename);
  free(res.lpf);
  return 0;
}
