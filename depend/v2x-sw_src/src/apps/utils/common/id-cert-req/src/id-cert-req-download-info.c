/** 
  * @file 
  * @brief 식별인증서 다운로드일정정보 다운로드 관련 구현
  * @date 2022-08-13 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <sys/stat.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

// 유틸리티 헤더 파일
#include "id-cert-req.h"


/**
 * @brief 식별인증서 다운로드일정정보를 다운로드한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int ID_CERT_REQ_DownloadIdCertDownloadInfo(void)
{
  struct Dot2CertDownloadInfoRequestParams params;
  struct Dot2CertDownloadInfoDownloadResult res;
  memset(&params, 0, sizeof(params));

  /*
   * 필요한 정보를 파일에서 로딩한다.
   */
  // 인증서발급요청문 H8
  uint8_t req_h8[8];
  int ret = ID_CERT_REQ_ImportFile(g_cfg.req_h8_file, req_h8, 8, 8);
  if (ret < 0) {
    printf("Fail to import %s\n", g_cfg.req_h8_file);
    return -1;
  }

  /*
   * API 파라미터를 설정한다.
   */
  memcpy(params.req_h8, req_h8, 8);
  params.cert_dl_url = g_cfg.info.download_info_req_url;

  /*
   * 인증서 다운로드일정정보 다운로드를 수행한다.
   */
  res = Dot2_DownloadCertDownloadInfo(&params);
  if (res.ret < 0) {
    printf("Fail to Dot2_DownloadCertDownloadInfo() : %d\n", res.ret);
    return -1;
  }

  /*
   * 결과를 화면에 출력한다.
   */
  printf("CertDownloadTime: %u\n", res.cert_dl_time);
  printf("CurremtTime32: %u\n", res.current_time);
  printf("Remained seconds to CertDowloadTime: %d\n", res.remained_cert_dl_time);

  return 0;
}
