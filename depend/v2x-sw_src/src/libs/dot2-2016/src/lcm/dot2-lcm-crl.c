/**
  * @file
  * @brief CRL 관련 구현
  * @date 2022-12-10
  * @author gyun
  */


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief CRL 테이블을 초기화한다.
 */
void INTERNAL dot2_InitCRLTable(void)
{
  Log(kDot2LogLevel_Event, "Initialize CRL table\n");

  struct Dot2CRLTable *table = &(g_dot2_mib.crl);
  memset(table, 0, sizeof(struct Dot2CRLTable));

  dot2_InitHashBasedCRLTable(&(table->hash));
  dot2_InitLVBasedCRLTable(&(table->lv));
}


/**
 * @brief CRL 테이블을 해제한다.
 */
void INTERNAL dot2_ReleaseCRLTable(void)
{
  Log(kDot2LogLevel_Event, "Release CRL table\n");
  struct Dot2CRLTable *table = &(g_dot2_mib.crl);
  dot2_FlushHashBasedCRLTable(&(table->hash));
  dot2_FlushLVBasedCRLTable(&(table->lv));
}


/**
 * @brief 인증서가 만기되었는지 확인한다. (=CRL 테이블에 정보가 존재하는지 확인한다)
 * @param[in] cert_id 인증서ID 정보 구조체
 * @param[in] h10 인증서 H10 값 (Hash 기반 CRL이 사용되는 인증서(=익명인증서를 제외한 모든 인증서)인 경우에만 사용됨)
 * @return 만기되었는지 여부
 *
 * CRL 테이블 내에 동일한 H10이나 LV 값이 존재하면, 해당 인증서는 폐기된 것이다.
 */
bool INTERNAL dot2_CheckCertRevocation(struct Dot2CertId *cert_id, const uint8_t *h10)
{
  struct Dot2CRLTable *table = &(g_dot2_mib.crl);
  bool ret = false;
  if (cert_id->type == kDot2CertIdType_LinkageData) {
    if (dot2_FindLVBasedCertRevocationEntry_2(&(table->lv), cert_id->u.linkage_data.i, cert_id->u.linkage_data.val)) {
      ret = true;
    }
  } else {
    if (dot2_FindHashBasedCertRevocationEntry(&(table->hash), h10)) {
      ret = true;
    }
  }
  return ret;
}


/**
 * @brief 서버에 요청하여 CRL을 다운로드한다.
 * @param[out] crl CRL 바이트열이 저장될 버퍼 포인터
 * @retval 양수: CRL 바이트열의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_DownloadCRL(uint8_t **crl)
{
  int ret;
  Log(kDot2LogLevel_Event, "Download CRL\n");

  struct Dot2HTTPSMessage resp_msg = { NULL, 0 };

  /*
   * HTTPS 접속 정보를 가져온다.
   */
  struct Dot2HTTPSConnInfo info;
  pthread_mutex_lock(&(g_dot2_mib.mtx));
  dot2_HTTPS_GetHTTPSConnInfo(&info);
  pthread_mutex_unlock(&(g_dot2_mib.mtx));
  if ((info.crl_url == NULL) ||
      (info.rca_tls_cert_file_path == NULL)) {
    Err("Fail to download CRL - no HTTPS connection info\n");
    ret = -kDot2Result_LCM_HTTPS_NoConnectionInfo;
    goto out;
  }

  /*
   * 서버에 HTTPS Get 하여 CRL을 다운로드한다.
   */
  struct Dot2HTTPSFileName resp_filename;
  ret = dot2_HTTPS_GET(info.crl_url, info.rca_tls_cert_file_path, NULL, 0, NULL, &resp_filename, &resp_msg);
  if (ret < 0) {
    goto out;
  }

  /*
   * 결과를 반환한다.
   */
  int crl_size = (int)(resp_msg.len);
  *crl = malloc(crl_size);
  if (*crl == NULL) {
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  memcpy(*crl, resp_msg.octs, crl_size);
  ret = crl_size;

out:
  if (resp_msg.octs) { free(resp_msg.octs); }
  dot2_HTTPS_ClearHTTPSConnInfo(&info);
  return ret;
}
