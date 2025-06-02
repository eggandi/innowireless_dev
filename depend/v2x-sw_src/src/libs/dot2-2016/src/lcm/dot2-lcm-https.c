/** 
  * @file 
  * @brief HTTPS 관련 구현
  * @date 2022-07-27 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"


/**
 * @brief HTTPS POST/GET Response 메시지 수신 시 호출되는 콜백함수. 수신된 데이터를 userp(=Dot2HTTPSData)에 저장한다.
 * @param[in] contents 수신 데이터
 * @param[in] size 수신 데이터 블록 크기
 * @param[in] nmemb 수신 데이터 블록 개수
 * @param[in] userp 사용자 private 데이터(=Dot2HTTPSData). 수신된 Response 데이터를 저장한다.
 * @return 처리한 데이터길이
 * @retval 0: 실패
 *
 * TODO:: size * nmemb 최대길이 확인
 */
size_t INTERNAL dot2_HTTPS_ResponseCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t ret = 0, realsize = size * nmemb;
  struct Dot2HTTPSMessage *resp = (struct Dot2HTTPSMessage *)userp;
  resp->octs = realloc(resp->octs, resp->len + realsize + 1);
  if (resp->octs) {
    memcpy(&(resp->octs[resp->len]), contents, realsize);
    resp->len += realsize;
    resp->octs[resp->len] = 0;
    ret = realsize;
  }
  return ret;
}


/**
 * @brief 문자열(str1) 내에서 특정 문자열(str2)을 찾아 시작지점 포인터를 반환한다. (대소문자 구분 없이)
 * @param[in] str1 문자열 포인터 변수
 * @param[in] str2 특정 문자열 포인터 변수
 * @return 일치하는 문자열의 시작위치에 대한 문자열 포인터
 * @retval NULL: 실패
 */
static char * dot2_HTTPS_GetStr(const char *str1, const char *str2)
{
  size_t size = strlen(str2);
  while (*str1) {
    if (strncasecmp(str1, str2, 1) == 0) {
      if (strncasecmp(str1, str2, size) == 0) {
        return (char *)str1;
      }
    }
    str1++;
  }
  return NULL;
}


/**
 * @brief 대소문자 구분없이 문자열(str1)에서 특정 문자열(str2)을 찾는다
 * @param[in] cd HTTP GET 응답헤더에서 Content-disposition 전체 문자열이 담긴 문자열 포인터
 * @param[out] filename Content-disposition 전체 문자열에서 filename에 해당되는 문자열이 복사될 구조체 포인터
 */
static void dot2_HTTPS_GetFileName(char const*const cd, struct Dot2HTTPSFileName *filename)
{
  const char *cd_tag = "Content-Disposition: ";
  const char *key = "filename=";
  char *ptr;

  ptr = dot2_HTTPS_GetStr(cd, key);
  if (ptr == NULL) {
    Err("Fail to get file name from HTTPS header - No key-value for \"%s\" in \"%s\" \n", key, cd_tag);
    filename->res = -kDot2Result_LCM_HTTPS_NoKeyValueInHeader;
    return;
  }

  // 파일이름 시작지점 설정(+1은 큰 따옴표 제외)
  ptr += strlen(key) + 1;

  // 파일이름 복사하기
  size_t len = 0;
  while ((*ptr != '\0') && (*ptr != ';') && (*ptr !=  '"')) {
    filename->str[len] = *ptr;
    len++;
    ptr++;
    if (len >= sizeof(filename->str)) {
      Err("Fail to get file name from HTTPS header - Too long file name(%zu)\n", len);
      filename->res = -kDot2Result_LCM_HTTPS_InvalidFileNameLenInHeader;
      return;
    }
  }
  filename->str[len] = '\0';
  if (len == 0) {
    filename->res = -kDot2Result_LCM_HTTPS_InvalidFileNameLenInHeader;
  } else {
    filename->res = kDot2Result_Success;
  }
}


/**
 * @brief HTTP Response 메시지 수신 시 호출되는 콜백함수. 수신 메시지 헤더에 수납된 데이터를 userdata에 저장한다.
 * @param[in] contents 수신된 헤더 내 데이터
 * @param[in] size  크기
 * @param[in] nitems 데이터 갯수
 * @param[in] userdata 응답문 헤더 중 원하는 내용을 담을 사용자 구조체
 * @return cb 헤더 데이터의 크기 (size * nmeb 값)
 *
 * 이 함수는 libcurl에서 사용되고 만들어진 기본 함수(header_callback)이다.
 * Content-Type의 filename을 파싱하기 위해 수정되었다.
 */
size_t INTERNAL dot2_HTTPS_ResponseHdrCallback(const char *contents, size_t size, size_t nitems, void *userdata)
{
  const size_t cb = size * nitems;
  const char *header_str = contents;
  struct Dot2HTTPSFileName *filename = (struct Dot2HTTPSFileName *)userdata;
  const char *filename_tag = "Content-Disposition:";
  if (!strncasecmp(header_str, filename_tag, strlen(filename_tag))) {
    dot2_HTTPS_GetFileName(header_str + strlen(filename_tag), filename);
  }
  return cb;
}


/**
 * @brief MIB에 저장된 HTTPS 접속 관련 정보를 복사해온다.
 * @param[in] info 정보가 저장될 구조체 포인터
 */
void INTERNAL dot2_HTTPS_GetHTTPSConnInfo(struct Dot2HTTPSConnInfo *info)
{
  memset(info, 0, sizeof(struct Dot2HTTPSConnInfo));

  if (g_dot2_mib.lcm.ra.lpf_url) {
    info->lpf_url = strdup(g_dot2_mib.lcm.ra.lpf_url);
  }
  if (g_dot2_mib.lcm.ra.lccf_url) {
    info->lccf_url = strdup(g_dot2_mib.lcm.ra.lccf_url);
  }
  if (g_dot2_mib.lcm.ra.crl_url) {
    info->crl_url = strdup(g_dot2_mib.lcm.ra.crl_url);
  }
  if (g_dot2_mib.lcm.ra.acp_url) {
    info->acp_url = strdup(g_dot2_mib.lcm.ra.acp_url);
  }
  if (g_dot2_mib.lcm.ra.pcp_url) {
    info->pcp_url = strdup(g_dot2_mib.lcm.ra.pcp_url);
  }
  if (g_dot2_mib.lcm.ra.icp_url) {
    info->icp_url = strdup(g_dot2_mib.lcm.ra.icp_url);
  }
  if (g_dot2_mib.lcm.tls.rca_cert_file_path) {
    info->rca_tls_cert_file_path = strdup(g_dot2_mib.lcm.tls.rca_cert_file_path);
  }
}


/**
 * @brief HTTPS 접속 관련 정보를 제거한다.
 * @param[in] info HTTPS 접속 관련 정보
 */
void INTERNAL dot2_HTTPS_ClearHTTPSConnInfo(struct Dot2HTTPSConnInfo *info)
{
  if (info->lpf_url) { free(info->lpf_url); }
  if (info->lccf_url) { free(info->lccf_url); }
  if (info->crl_url) { free(info->crl_url); }
  if (info->acp_url) { free(info->acp_url); }
  if (info->pcp_url) { free(info->pcp_url); }
  if (info->icp_url) { free(info->icp_url); }
  if (info->rca_tls_cert_file_path) { free(info->rca_tls_cert_file_path); }
  info->lpf_url = NULL;
  info->lccf_url = NULL;
  info->crl_url = NULL;
  info->acp_url = NULL;
  info->pcp_url = NULL;
  info->icp_url = NULL;
  info->rca_tls_cert_file_path = NULL;
}
