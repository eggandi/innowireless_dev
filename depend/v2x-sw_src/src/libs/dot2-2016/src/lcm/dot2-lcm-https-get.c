/** 
  * @file 
  * @brief HTTPS GET 관련 구현
  * @date 2022-07-27 
  * @author gyun 
  */

// 시스템 헤더 파일
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "curl/curl.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "lcm/dot2-lcm.h"


/**
 * @brief 메시지 바이트열을 Base64로 인코딩한다
 * @param[in] prefix 인코딩된 메시지 바이트열 앞에 추가되는 프리픽스 문자열
 * @param[in] msg 메시지 바이트열
 * @param[in] msg_size msg의 길이
 * @return Base64 인코딩된 문자열 (사용 후 free()해 주어야 한다)
 * @retval NULL: 실패
 */
static char * dot2_EncodeBase64(const char *prefix, const uint8_t *msg, size_t msg_size)
{
  /*
   * base64 인코딩을 수행한다.
   */
  char encoding_table[64] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                             'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                             'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                             'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                             'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                             'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                             'w', 'x', 'y', 'z', '0', '1', '2', '3',
                             '4', '5', '6', '7', '8', '9', '+', '/'};
  size_t encoded_size = 4 * ((msg_size + 2) / 3);
  char *encoded_data = calloc(1, encoded_size);
  if (encoded_data == NULL) {
    return NULL;
  }
  for (unsigned int i = 0, j = 0; i < msg_size;) {
    uint32_t octet_a = i < msg_size ? (unsigned char)msg[i++] : 0;
    uint32_t octet_b = i < msg_size ? (unsigned char)msg[i++] : 0;
    uint32_t octet_c = i < msg_size ? (unsigned char)msg[i++] : 0;
    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }
  int mod_table[3] = {0, 2, 1};
  for (int i = 0; i < mod_table[msg_size % 3]; i++) {
    encoded_data[encoded_size - 1 - i] = '=';
  }

  /*
   * 프리픽스가 있을 경우 앞에 프리픽스를 추가한다.
   */
  char *ptr = encoded_data;
  if (prefix) {
    size_t prefix_size = strlen(prefix);
    ptr = calloc(1, prefix_size + encoded_size);
    if (ptr == NULL) {
      free(encoded_data);
      return NULL;
    }
    memcpy(ptr, prefix, prefix_size);
    memcpy(ptr + prefix_size, encoded_data, encoded_size);
    free(encoded_data);
  }

  return ptr;
}


/**
 * @brief 서버로 HTTPS GET request 메시지를 송신하여 response 메시지를 수신한다.
 * @param[in] url HTTPS GET request 메시지를 전송할 URL
 * @param[in] rca_tls_cert_file_path root ca TLS 인증서 파일 경로
 * @param[in] hdr_msg HTTPS GET request 메시지 헤더의 ‘Download-Req’에 포함될 바이트열 (NULL 가능)
 * @param[in] hdr_msg_size hdr_msg의 길이
 * @param[in] current_filename 현재 보유한 파일명 -> If-None-Match 옵션과 함께 HTTPS 헤더에 수납된다. (NULL 가능)
 * @param[out] resp_filename HTTPS Get response 메시지 헤더내 수납된 파일명이 저장될 구조체 포인터 (NULL 가능)
 * @param[out] resp_msg 서버로부터 수신된 response 메시지 내 데이터가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_HTTPS_GET(
  const char *url,
  const char *rca_tls_cert_file_path,
  const uint8_t *hdr_msg,
  Dot2SPDUSize hdr_msg_size,
  const char *current_filename,
  struct Dot2HTTPSFileName *resp_filename,
  struct Dot2HTTPSMessage *resp_msg)
{
  int ret;
  CURLcode res;
  Log(kDot2LogLevel_Event, "HTTPS GET - %s\n", url);
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
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_SSLVERSION) failed: %s\n", curl_easy_strerror(res));
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
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_URL) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /**
   * HTTPS가 GET method를 사용하도록 한다
   * 1 은 HTTP 요청이 GET을 사용하도록 강제한다
   */
  res = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_HTTPGET) failed: %s\n", curl_easy_strerror(res));
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
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_CAINFO) failed: %s\n", curl_easy_strerror(res));
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
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_SSL_VERIFYPEER) failed: %s\n", curl_easy_strerror(res));
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
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_SSL_VERIFYHOST) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /**
   * HTTP GET request header를 설정한다.
   * 1. HTTP Header의 ‘Download-Req’에 Base64 인코딩 되어 있는 ADRequest 포함 (ADR 요청문 메시지 이외의 경우 NULL값을 갖는다)
   * (ex) Download-Req : "인코딩된 메시지"
   * 2. HTTP Header에 "If-None-Match" 사용. (다운로드할 서버의 파일이 바뀌지 않았다면 "응답코드 304: 변경사항 없음"이 리턴된다.)
   * (ex) If-None-Match : “global_policy_0001.oer”
   */
  header_list = curl_slist_append(header_list, "Content-Type: application/octet-stream");
  if (hdr_msg){
    char *base64_msg = dot2_EncodeBase64("Download-Req: ", hdr_msg, hdr_msg_size);
    if (base64_msg) {
      header_list = curl_slist_append(header_list, base64_msg);
      free(base64_msg);
    }
  }
  if (current_filename) {
    const char *prefix = "If-None-Match: ";
    size_t prefix_size = strlen(prefix);
    size_t current_filename_size = strlen(current_filename);
    char *line = calloc(1, prefix_size + current_filename_size);
    if (line == NULL) {
      ret = -kDot2Result_NoMemory;
      goto out;
    }
    memcpy(line, prefix, prefix_size);
    memcpy(line + prefix_size, current_filename, current_filename_size);
    header_list = curl_slist_append(header_list, line);
  }
  res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list); // 헤더 완성
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_HTTPHEADER) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /**
   * 파일 이름이 필요한 경우, HTTP GET response header에서 filename을 파싱한다.
   * 인가되지 않은 파일 다운로드 요청(HTTP GET)시 사용된다. 즉, LCCF/LPF를 요청할 때 해당한다.
   */
  if (resp_filename) {
    res = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, dot2_HTTPS_ResponseHdrCallback);
    if (res != CURLE_OK) {
      Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_HEADERFUNCTION) failed: %s\n", curl_easy_strerror(res));
      ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
      goto out;
    }
    memset(resp_filename, 0, sizeof(struct Dot2HTTPSFileName));
    res = curl_easy_setopt(curl, CURLOPT_HEADERDATA, resp_filename);
    if (res != CURLE_OK) {
      Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_HEADERDATA) failed: %s\n", curl_easy_strerror(res));
      ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
      goto out;
    }
  }

  /*
   * HTTPS GET response 수신 설정한다.
   */
  res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dot2_HTTPS_ResponseCallback); // response 메시지를 처리할 콜백함수 등록
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_WRITEFUNCTION) failed: %s\n", curl_easy_strerror(res));
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
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_WRITEDATA) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }
  res = curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, DOT2_HTTPS_RESPONSE_WAIT_TIMEOUT); // 타임아웃 설정
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_GET - curl_easy_setopt(CURLOPT_TIMEOUT_MS) failed: %s\n", curl_easy_strerror(res));
    ret = -kDot2Result_LCM_HTTPS_curl_easy_setopt;
    goto out;
  }

  /*
   * HTTPS GET을 실행한다.
   */
  long http_code;
#ifdef _UNIT_TEST_
   // 테스트벡터 HTTPS response 메시지를 3번에 나눠 강제 수신하고, 테스트벡터 결과값을 강제 세팅한다.
   // 필요시, 테스트벡터 HTTPS response 헤더 메시지들도 수신한다. (LCCF/LPF 요청 케이스)
  uint8_t *resp = g_dot2_mib.lcm.test.https_resp_tv.resp;
  size_t seg_size = g_dot2_mib.lcm.test.https_resp_tv.resp_size / 3;
  size_t last_seg_size = seg_size + (g_dot2_mib.lcm.test.https_resp_tv.resp_size % 3);
  dot2_HTTPS_ResponseCallback(resp, seg_size, 1, resp_msg);
  dot2_HTTPS_ResponseCallback(resp + seg_size, 1, seg_size, resp_msg);
  dot2_HTTPS_ResponseCallback(resp + (2 * seg_size), last_seg_size, 1, resp_msg);
  if (resp_filename) {
    for (unsigned int i = 0; i < g_dot2_mib.lcm.test.https_resp_tv.resp_hdr_num; i++) {
      dot2_HTTPS_ResponseHdrCallback(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i],
                                     strlen(g_dot2_mib.lcm.test.https_resp_tv.resp_hdr[i]),
                                     1,
                                     resp_filename);
    }
  }
  res = g_dot2_mib.lcm.test.https_resp_tv.res;
  http_code = g_dot2_mib.lcm.test.https_resp_tv.http_code;
#else
  res = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
#endif
  if (res != CURLE_OK) {
    Err("Fail to dot2_HTTPS_GET() - curl_easy_perform() failed: %s, code: %d\n", curl_easy_strerror(res), http_code);
    ret = -kDot2Result_LCM_HTTPS_curl_easy_perform;
    goto out;
  }

  Log(kDot2LogLevel_Event, "%zu-bytes HTTPS GET response received - http code: %d\n", resp_msg->len, http_code);
  ret = kDot2Result_Success;
  if ((resp_filename) && (resp_filename->res < 0)) {
    ret = resp_filename->res;
  } else {
    if (http_code == DOT2_HTTPS_CODE_NOT_MODIFIED) {
      ret = -kDot2Result_LCM_HTTPS_NoModifiedFile;
    } else if (http_code == DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE) {
      ret = -kDot2Result_LCM_HTTPS_DownloadInfoUnvailable;
    } else if (http_code == DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR) {
      ret = -kDot2Result_LCM_HTTPS_ServerError;
    } else if ((http_code != DOT2_HTTPS_CODE_OK) || (resp_msg->len == 0) || !resp_msg->octs) {
      Err("Fail to dot2_HTTPS_GET() - http code(%d) is not OK or zero-length response(len:%u) or no memory(%p)\n",
          http_code, resp_msg->len, resp_msg->octs);
      ret = -kDot2Result_LCM_HTTPS_InvalidResponse;
    }
  }

out:
  curl_slist_free_all(header_list);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return ret;
}
