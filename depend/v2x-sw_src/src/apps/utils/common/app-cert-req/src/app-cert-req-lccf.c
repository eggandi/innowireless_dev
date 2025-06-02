/** 
  * @file 
  * @brief LCCF 다운로드 관련 구현
  * @date 2022-07-31 
  * @author gyun 
  */



// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "app-cert-req.h"


/**
 * @brief LCCF를 다운로드한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int APP_CERT_REQ_DownloadLCCF(void)
{
  char *current_filename = NULL;
  if (g_cfg.lccf.current_filename_present) {
    current_filename = g_cfg.lccf.current_filename;
  }

  struct Dot2LCCFRequestResult res;
  res = Dot2_DownloadLCCF(current_filename);
  if (res.ret == -kDot2Result_LCM_HTTPS_NoModifiedFile) {
    printf("LCCF download result: No modified file in server, use current file\n");
    return 0;
  } else if (res.ret < 0) {
    printf("Fail to Dot2_DownloadLCCF() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  printf("LCCF filename: %s\n", res.lccf_filename);
  APP_CERT_REQ_PrintOcts("LCCF", res.lccf, res.lccf_size);
  if (res.rca_cert) {
    APP_CERT_REQ_PrintOcts("RCA", res.rca_cert, res.rca_cert_size);
  } else {
    printf("Error: No RCA cert in LCCF\n");
  }
  if (res.ica_cert) {
    APP_CERT_REQ_PrintOcts("ICA", res.ica_cert, res.ica_cert_size);
  } else {
    printf("Error: No ICA certin LCCF\n");
  }
  if (res.pca_cert) {
    APP_CERT_REQ_PrintOcts("PCA", res.pca_cert, res.pca_cert_size);
  } else {
    printf("Error: No PCA cert in LCCF\n");
  }
  if (res.crlg_cert) {
    APP_CERT_REQ_PrintOcts("CRLG", res.crlg_cert, res.crlg_cert_size);
  } else {
    printf("No CRLG cert in LCCF\n");
  }

  /*
   * 결과를 파일에 저장한다.
   */
  APP_CERT_REQ_ExportFile(res.lccf_filename, res.lccf, res.lccf_size); // LCCF
  if (res.rca_cert) {
    APP_CERT_REQ_ExportFile(g_cfg.rca_file, res.rca_cert, res.rca_cert_size); // RCA 인증서
  }
  if (res.ica_cert) {
    APP_CERT_REQ_ExportFile(g_cfg.ica_file, res.ica_cert, res.ica_cert_size); // ICA 인증서
  }
  if (res.pca_cert) {
    APP_CERT_REQ_ExportFile(g_cfg.pca_file, res.pca_cert, res.pca_cert_size); // PCA 인증서
  }
  if (res.crlg_cert) {
    APP_CERT_REQ_ExportFile(g_cfg.lccf.crlg_file, res.crlg_cert, res.crlg_cert_size); // PCA 인증서
  }

  free(res.lccf_filename);
  free(res.lccf);
  if (res.rca_cert) { free(res.rca_cert); }
  if (res.ica_cert) { free(res.ica_cert); }
  if (res.pca_cert) { free(res.pca_cert); }
  if (res.crlg_cert) { free(res.crlg_cert); }
  return 0;
}
