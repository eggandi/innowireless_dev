/**
  * @file
  * @brief CRL 다운로드 유틸리티 메인 파일
  * @date 2022-12-10
  * @author gyun
  */


// 시스템 헤더 파일
#include <stdio.h>
#include <string.h>

// 유틸리티 헤더 파일
#include "crl-req.h"


/*
 * 각 입력파라미터들의 기본값 (입력하지 않았을 경우에 적용되는 값)
 */
const char *g_default_rca_cert_file = "root.oer";
const char *g_default_ica_cert_file = "ICA.oer";
const char *g_default_pca_cert_file = "PCA.oer";
const char *g_default_ra_cert_file = "RA.oer";
const char *g_default_crlg_cert_file = "CRLG.oer";
const char *g_default_rca_tls_cert_file = "/etc/ssl/certs/bad7b270.0";
const char *g_default_req_url = "https://ra.scms.co.kr:8894/download-crl";
const char *g_default_crl_file = "CompositeCrl.oer";

struct CRLReqCFG g_cfg; ///< 유틸리티 설정정보


/**
 * @brief 유틸리티 프로그램 사용법을 출력한다.
 * @param[in] app_filename 프로그램 실행파일명
 */
static void CRL_REQ_Usage(const char *app_filename)
{
  printf("\n\n Description: CRL request utility using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s down|load [OPTIONS]\n\n", app_filename);
  printf("          down: Download CRL\n");
  printf("          load: Load CRL file\n");

  printf("\n OPTIONS for \"down\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --rca_tls <file path>    [INPUT]  Set RootCA TLS cert file path. If not specified, set to \"%s\"\n", g_default_rca_tls_cert_file);
  printf("  --url <URL>              [INPUT]  Set URL for CRL download request. If not specified, set to \"%s\"\n", g_default_req_url);
  printf("  --crl_file <file path>   [OUTPUT] Set CRL file export path for verification. If not specified, set to \"%s\"\n", g_default_crl_file);;
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"load\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --crlg <file path>       [INPUT]  Set OER-encoded CRLG cert file path. If not specified, set to \"%s\"\n", g_default_crlg_cert_file);
  printf("  --crl_file <file path>   [INPUT]  Set OER-encoded CRL file path. If not specified, set to \"%s\"\n", g_default_crl_file);;
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s down\n", app_filename);
  printf("  2) %s load\n", app_filename);
  printf("\n");
}


/**
 * @brief 유틸리티 메인 함수
 * @param[in] argc 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 개수 (유틸리티 실행파일명 포함)
 * @param[in] argv 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (유틸리티 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int main(int argc, char *argv[])
{
  /*
   * 아무 파라미터 없이 실행하면 사용법을 출력한다.
   */
  if (argc < 2) {
    CRL_REQ_Usage(argv[0]);
    return 0;
  }

  printf("Running CRL download utility\n");
  memset(&g_cfg, 0, sizeof(g_cfg));

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  int ret = CRL_REQ_ParsingInputParameters(argc, argv);
  if (ret < 0) {
    return -1;
  }

  /*
   * dot2 라이브러리를 초기화한다.
   */
  ret = Dot2_Init(g_cfg.lib_dbg, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default);
  if (ret < 0) {
    printf("Fail to Dot2_Init() : %d\n", ret);
    return -1;
  }

  /*
   * SCC 인증서들을 로딩한다.
   */
  ret = CRL_REQ_LoadSCCCertFiles();
  if (ret < 0) {
    return -1;
  }

  /*
   * LCM 설정을 수행한다.
   */
  ret = CRL_REQ_ConfigLCM();
  if (ret < 0) {
    return -1;
  }

  /*
   * 동작 유형에 따른 동작을 수행한다.
   */
  if (g_cfg.op == kCRLReqOperationType_Download) {
    CRL_REQ_DownloadCRL();
  } else { // load
    CRL_REQ_LoadCRLFile();
  }

  return 0;
}


/**
 * @brief 설정정보를 화면에 출력한다.
 */
void CRL_REQ_PrintCFG(void)
{
  if (g_cfg.op == kCRLReqOperationType_Download) {
    printf("Download opeation CFG\n");
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.rca_file);
    printf("  [INPUT]  ICA cert file path: %s\n", g_cfg.ica_file);
    printf("  [INPUT]  PCA cert file path: %s\n", g_cfg.pca_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.ra_file);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.down.rca_tls_cert_file);
    printf("  [INPUT]  Download request URL: %s\n", g_cfg.down.req_url);
    printf("  [OUTPUT] CRL file export path: %s\n", g_cfg.crl_file);
  } else {
    printf("Load opeation CFG\n");
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.rca_file);
    printf("  [INPUT]  ICA cert file path: %s\n", g_cfg.ica_file);
    printf("  [INPUT]  PCA cert file path: %s\n", g_cfg.pca_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.ra_file);
    printf("  [INPUT]  CRLG cert file path: %s\n", g_cfg.load.crlg_file);
    printf("  [INPUT]  CRL file path: %s\n", g_cfg.crl_file);
  }
}


/**
 * @brief LCM 설정을 수행한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CRL_REQ_ConfigLCM(void)
{
  if (g_cfg.op == kCRLReqOperationType_Download) {
    /*
     * RootCA TLS 인증서 파일 경로를 설정한다.
     */
    int ret = Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_cfg.down.rca_tls_cert_file);
    if (ret < 0) {
      return -1;
    }

    /*
     * CRL 요청 URL을 설정한다.
     */
    ret = Dot2_ConfigLCM(kDot2LCMConfigType_CRLReqURL, g_cfg.down.req_url);
    if (ret < 0) {
      return -1;
    }
  }

  return 0;
}


/**
 * @brief 바이트열을 HexString 형태로 화면에 출력한다.
 * @param[in] desc 바이트열 설명문
 * @param[in] octs 출력할 바이트열
 * @param[in] len 출력할 바이트열의 길이
 */
void CRL_REQ_PrintOcts(const char *desc, const uint8_t *octs, size_t len)
{
  printf("%s(%zu): ", desc, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(octs + i));
  }
  printf("\n");
}