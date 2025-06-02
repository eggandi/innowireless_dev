/** 
  * @file 
  * @brief HTTPS POST 관련 구현
  * @date 2022-07-24 
  * @author gyun 
  */


//시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "curl/curl.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "lcm/dot2-lcm.h"


/**
 * @brief 서버로 HTTPS POST request를 송신하고 response를 수신한다.
 * @param[in] url request를 전송할 URL
 * @param[in] rca_tls_cert_file_path root ca TLS 인증서 파일 경로
 * @param[in] req_msg request 메시지에 수납될 메시지 바이트열
 * @param[in] req_msg_size req_msg의 길이
 * @param[out] resp_msg 서버로부터 수신된 response 메시지 내 데이터가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_HTTPS_POST(
  const char *url,
  const char *rca_tls_cert_file_path,
  const uint8_t *req_msg,
  Dot2SPDUSize req_msg_size,
  struct Dot2HTTPSMessage *resp_msg)
{
  int ret;
  CURLcode res;
  Log(kDot2LogLevel_Event, "HTTPS POST\n");
  struct curl_slist *header_list = NULL;

  /*
   * CURL을 초기화한다.
   */
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  if (!curl) {
    return -kDot2Result_LCM_HTTPS_curl_easy_init;
  }

  /*
   * tls1.2 버전과 해당되는 cipher suites로 설정한다.
   * 이 버전에 ECDHE-ECDSA-AES128-SHA256 cipher suites 들어있음
   * [국내규격] 최소 ECDHE-ECDSA-AES128-SHA256 지원해야 함
   */
  res = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_MAX_TLSv1_2);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_SSLVERSION) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * HTTP 연결할 서버의 URL을 지정한다.
   * 예: https://ra.scms.or.kr:8892/provision-application-certificate
   * curl_easy_setopt(curl, CURLOPT_URL, "https://192.168.123.240:8892/provision-application-certificate");
   */
  res = curl_easy_setopt(curl, CURLOPT_URL, url);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_URL) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /**
   * HTTPS가 POST method를 사용하도록 한다
   */
  res = curl_easy_setopt(curl, CURLOPT_POST, 1L);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_POST) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * 지정된 인증서 파일을 사용하여 피어의 서버를 확인하도록 curl에 지시한다.
   * CURLOPT_CAINFO: sets the file name to load CA certs from
   * CURLOPT_CAPATH: sets the directory (for primarily OpenSSL-using libcurl versions) in which single CA certs are stored
   * 1. CAPATH 사용한 경우
   *  curl_easy_setopt(curl, CURLOPT_CAPATH,  "/etc/ssl/certs");
   * 2. CAINFO 사용한 경우
   *  curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/4932ca72.0");
   * >>만약 CAINFO가 된다면 root.tls 인증서를 해시값으로 이름을 변경 후 root 인증서이므로 .0으로 저장하는 과정을 추가해야 함
   */
  res = curl_easy_setopt(curl, CURLOPT_CAINFO, rca_tls_cert_file_path);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_CAINFO) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * 통신하고자 하는 서버의 인증서가 인증된 것인지 여부를 curl에서 확인. 해당 인증서의 경로를 나타냄
   * 1 은 활성화
   * 0 은 비활성화
   *
   * NOTE:: 서버에 따라서 아래 옵션을 활성화시키면 안되는 경우가 있음
   *  - A사 서버의 경우, 아래 옵션을 활성화시키면 발급요청에 실패함
   *    (curl_easy_perform() failed: Problem with the SSL CA cert (path? access rights?))
   */
  res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_SSL_VERIFYPEER) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * 통신하고자 하는 서버의 인증서 이름이 CURL로 연결하도록 지시한 URL hostname과 일지할 때 안전하다고 판단
   * 1 은 SSL 피어 인증서의 일반 이름의 존재를 확인합니다.
   * 2 를 사용하여 공통 이름이 있는지 확인하고 제공된 호스트 이름과 일치하는지 확인
   * 0 은 이름을 확인하지 않음.
   *
   * NOTE:: 서버에 따라서 아래 옵션을 활성화시키면 안되는 경우가 있음
   *  - B사 서버의 경우, 아래 옵션을 활성화시키면 발급요청에 실패함
   *    (curl_easy_perform() failed: SSL peer certificate or SSH remote key was not OK)
   */
  res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_SSL_VERIFYHOST) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * HTTPS POST request를 설정한다.
   */
  header_list = curl_slist_append(header_list, "Content-Type: application/octet-stream");
  res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list); // 헤더 완성
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_HTTPHEADER) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }
  res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req_msg_size); // body 설정
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_POSTFIELDSIZE) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }
  res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_msg); // body 설정
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_POSTFIELDS) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * HTTPS POST response 수신 설정한다.
   */
  res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dot2_HTTPS_ResponseCallback); // response 메시지를 처리할 콜백함수 등록
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_WRITEFUNCTION) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }
  resp_msg->octs = malloc(1);
  resp_msg->len = 0;
  if (!resp_msg->octs) {
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp_msg); // 콜백함수 내에서 response 메시지를 저장할 구조체 등록
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_WRITEDATA) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }
  res = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, DOT2_HTTPS_RESPONSE_WAIT_TIMEOUT); // 타임아웃 설정
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST - curl_easy_setopt(CURLOPT_TIMEOUT_MS) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * HTTPS POST를 실행한다.
   */
  long http_code;
#ifdef _UNIT_TEST_
  // 테스트벡터 HTTPS response 메시지를 3번에 나눠 강제 수신하고, 테스트벡터 결과값을 강제 세팅한다.
  uint8_t *resp = g_dot2_mib.lcm.test.https_resp_tv.resp;
  size_t seg_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size / 3;
  size_t last_seg_size = seg_size + (g_dot2_mib.lcm.test.https_resp_tv.resp_size % 3);
  dot2_HTTPS_ResponseCallback(resp, seg_size, 1, resp_msg);
  dot2_HTTPS_ResponseCallback(resp + seg_size, 1, seg_size, resp_msg);
  dot2_HTTPS_ResponseCallback(resp + (2 * seg_size), last_seg_size, 1, resp_msg);
  res = g_dot2_mib.lcm.test.https_resp_tv.res;
  http_code = g_dot2_mib.lcm.test.https_resp_tv.http_code;
#else
  res = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
#endif
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_POST() - curl_easy_perform() failed: %s, code: %d\n", curl_easy_strerror(res), http_code);
    ret = -kDot2Result_LCM_HTTPS_curl_easy_perform;
    goto out;
  }

  Log(kDot2LogLevel_Event, "%zu-bytes HTTPS POST response received - http code: %d\n", resp_msg->len, http_code);
  ret = kDot2Result_Success;
  if ((http_code != DOT2_HTTPS_CODE_OK) || (resp_msg->len == 0) || !resp_msg->octs) {
    Err("Fail to dot2_HTTPS_POST() - http code(%d) is not OK or zero-length response(len:%u) or no memory(%p)\n",
        http_code, resp_msg->len, resp_msg->octs);
    ret = -kDot2Result_LCM_HTTPS_InvalidResponse;
  }

out:
  curl_easy_cleanup(curl);
  curl_slist_free_all(header_list);
  curl_global_cleanup();
  return ret;
}
