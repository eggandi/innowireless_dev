/**
 * @file
 * @brief LCCF 관련 구현
 * @date 2022-07-12
 * @author gyun
 */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief LCCF 내 인증서들을 SCC 정보리스트에 추가한다.
 * @param[in] rca_cert RCA 인증서바이트열 (NULL 가능)
 * @param[in] rca_cert_size RCA 인증서바이트열의 길이
 * @param[in] ica_cert ICA 인증서바이트열 (NULL 가능)
 * @param[in] ica_cert_size ICA 인증서바이트열의 길이
 * @param[in] pca_cert PCA 인증서바이트열 (NULL 가능)
 * @param[in] pca_cert_size PCA 인증서바이트열의 길이
 * @param[in] crlg_cert CRLG 인증서바이트열 (NULL 가능)
 * @param[in] crlg_cert_size CRLG 인증서바이트열의 길이
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_AddLCCFCertsToSCCList(
  const uint8_t *rca_cert,
  Dot2CertSize rca_cert_size,
  const uint8_t *ica_cert,
  Dot2CertSize ica_cert_size,
  const uint8_t *pca_cert,
  Dot2CertSize pca_cert_size,
  const uint8_t *crlg_cert,
  Dot2CertSize crlg_cert_size)
{
  int ret;
  struct Dot2SCCCertInfoEntry *cert_info_entry;
  if (rca_cert) {
    cert_info_entry = dot2_AddSCCCert(rca_cert, rca_cert_size, &ret);
    if ((cert_info_entry == NULL) &&
        (ret != -kDot2Result_CERT_SameCertInTable)) {
      return ret;
    }
  }
  if (ica_cert) {
    cert_info_entry = dot2_AddSCCCert(ica_cert, ica_cert_size, &ret);
    if ((cert_info_entry == NULL) &&
        (ret != -kDot2Result_CERT_SameCertInTable)) {
      return ret;
    }
  }
  if (pca_cert) {
    cert_info_entry = dot2_AddSCCCert(pca_cert, pca_cert_size, &ret);
    if ((cert_info_entry == NULL) &&
        (ret != -kDot2Result_CERT_SameCertInTable)) {
      return ret;
    }
  }
  if (crlg_cert) {
    cert_info_entry = dot2_AddSCCCert(crlg_cert, crlg_cert_size, &ret);
    if ((cert_info_entry == NULL) &&
        (ret != -kDot2Result_CERT_SameCertInTable)) {
      return ret;
    }
  }
  return kDot2Result_Success;
}


/**
 * @brief 서버에 요청하여 LCCF를 다운로드한다.
 * @param[in] current_filename 현재 가지고 있는 LCCF 파일명 (NULL 가능)
 * @param[out] lccf_filename LCCF 파일명이 저장될 버퍼 포인터
 * @param[out] lccf LCCF 바이트열이 저장될 버퍼 포인터
 * @param[out] lccf_size LCCF 바이트열의 길이가 저장될 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_DownloadLCCF(const char *current_filename, char **lccf_filename, uint8_t **lccf, Dot2LCCFSize *lccf_size)
{
  int ret;
  Log(kDot2LogLevel_Event, "Download LCCF - current filename: %s\n", current_filename);

  struct Dot2HTTPSMessage resp_msg = { NULL, 0 };

  /*
   * HTTPS 접속 정보를 가져온다.
   */
  struct Dot2HTTPSConnInfo info;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_HTTPS_GetHTTPSConnInfo(&info);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if ((info.lccf_url == NULL) ||
      (info.rca_tls_cert_file_path == NULL)) {
    Err("Fail to download LCCF - no HTTPS connection info\n");
    ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    goto out;
  }

  /*
   * 서버에 HTTPS Get 하여 LCCF를 다운로드한다.
   */
  struct Dot2HTTPSFileName resp_filename;
  ret = dot2_HTTPS_GET(info.lccf_url, info.rca_tls_cert_file_path, NULL, 0, current_filename, &resp_filename, &resp_msg);
  if (ret < 0) {
    goto out;
  }

  /*
   * 결과를 반환한다.
   */
  size_t lccf_filename_len = strlen(resp_filename.str);
  *lccf_filename = calloc(1, lccf_filename_len);
  if (*lccf_filename == NULL) {
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  memcpy(*lccf_filename, resp_filename.str, lccf_filename_len);
  *lccf_size = resp_msg.len;
  *lccf = malloc(*lccf_size);
  if (*lccf == NULL) {
    free(*lccf_filename);
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  memcpy(*lccf, resp_msg.octs, *lccf_size);
  ret = kDot2Result_Success;

out:
  if (resp_msg.octs) { free(resp_msg.octs); }
  dot2_HTTPS_ClearHTTPSConnInfo(&info);
  return ret;
}
