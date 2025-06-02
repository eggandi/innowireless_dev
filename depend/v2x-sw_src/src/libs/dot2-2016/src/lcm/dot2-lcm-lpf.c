/** 
  * @file 
  * @brief LPF 관련 구현
  * @date 2022-07-31 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"


/**
 * @brief 서버에 요청하여 LPF를 다운로드한다.
 * @param[in] current_filename 현재 가지고 있는 LPF 파일명 (NULL 가능)
 * @param[in] res 결과가 저장될 구조체 포인터
 */
void INTERNAL dot2_DownloadLPF(const char *current_filename, struct Dot2LPFRequestResult *res)
{
  Log(kDot2LogLevel_Event, "Download LPF - current filename: %s\n", current_filename);

  struct Dot2HTTPSMessage resp_msg = { NULL, 0 };

  /*
   * HTTPS 접속 정보를 가져온다.
   */
  struct Dot2HTTPSConnInfo info;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_HTTPS_GetHTTPSConnInfo(&info);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if ((info.lpf_url == NULL) ||
      (info.rca_tls_cert_file_path == NULL)) {
    Err("Fail to download LPF - no HTTPS connection info\n");
    res->ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    return;
  }

  /*
   * 서버에 HTTPS Get 하여 LPF를 다운로드한다.
   */
  struct Dot2HTTPSFileName resp_filename;
  memset(&resp_filename, 0, sizeof(resp_filename));
  int ret = dot2_HTTPS_GET(info.lpf_url,
                           info.rca_tls_cert_file_path,
                           NULL,
                           0,
                           current_filename,
                           &resp_filename,
                           &resp_msg);
  if (ret < 0) {
    goto out;
  }

  /*
   * 결과를 반환한다.
   */
  size_t lpf_filename_len = strlen(resp_filename.str);
  res->lpf_filename = calloc(1, lpf_filename_len);
  if (res->lpf_filename == NULL) {
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  memcpy(res->lpf_filename, resp_filename.str, lpf_filename_len);
  size_t lpf_size = resp_msg.len;
  res->lpf = malloc(lpf_size);
  if (res->lpf == NULL) {
    free(res->lpf_filename);
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  memcpy(res->lpf, resp_msg.octs, lpf_size);
  res->lpf_size = lpf_size;

out:
  res->ret = ret;
  if (resp_msg.octs) { free(resp_msg.octs); }
  dot2_HTTPS_ClearHTTPSConnInfo(&info);
}
