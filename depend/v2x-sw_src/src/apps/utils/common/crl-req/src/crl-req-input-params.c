/**
  * @file
  * @brief CRL 다운로드 유틸리티 입력 파라미터 처리 기능 구현
  * @date 2022-12-10
  * @author gyun
  */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// 유틸리티 헤더 파일
#include "crl-req.h"


/**
 * @brief 입력 파라미터들에 대한 기본값을 설정한다.
 */
static void CRL_REQ_SetDefaultInputParameters(CRLReqOperationType op)
{
  g_cfg.lib_dbg = DEFAULT_LIB_DBG;
  snprintf(g_cfg.rca_file, MAXLINE, "%s", g_default_rca_cert_file);
  snprintf(g_cfg.ica_file, MAXLINE, "%s", g_default_ica_cert_file);
  snprintf(g_cfg.pca_file, MAXLINE, "%s", g_default_pca_cert_file);
  snprintf(g_cfg.ra_file, MAXLINE, "%s", g_default_ra_cert_file);
  snprintf(g_cfg.crl_file, MAXLINE, "%s", g_default_crl_file);

  if (op == kCRLReqOperationType_Download) {
    snprintf(g_cfg.down.rca_tls_cert_file, MAXLINE, "%s", g_default_rca_tls_cert_file);
    snprintf(g_cfg.down.req_url, MAXLINE, "%s", g_default_req_url);
  } else { // Load
    snprintf(g_cfg.load.crlg_file, MAXLINE, "%s", g_default_crlg_cert_file);
  }
}


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int CRL_REQ_ProcessParsedOption(int option)
{
  int ret = 0;
  switch (option) {
    case 0: { // "rca"
      memset(g_cfg.rca_file, 0, sizeof(g_cfg.rca_file));
      snprintf(g_cfg.rca_file, MAXLINE, "%s", optarg);
      break;
    }
    case 1: { // "ica"
      memset(g_cfg.ica_file, 0, sizeof(g_cfg.ica_file));
      snprintf(g_cfg.ica_file, MAXLINE, "%s", optarg);
      break;
    }
    case 2: { // "pca"
      memset(g_cfg.pca_file, 0, sizeof(g_cfg.pca_file));
      snprintf(g_cfg.pca_file, MAXLINE, "%s", optarg);
      break;
    }
    case 3: { // "ra"
      memset(g_cfg.ra_file, 0, sizeof(g_cfg.ra_file));
      snprintf(g_cfg.ra_file, MAXLINE, "%s", optarg);
      break;
    }
    case 4: { // "crlg"
      if (g_cfg.op == kCRLReqOperationType_Load) {
        memset(g_cfg.load.crlg_file, 0, sizeof(g_cfg.load.crlg_file));
        snprintf(g_cfg.load.crlg_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 5: { // rca_tls
      if (g_cfg.op == kCRLReqOperationType_Download) {
        memset(g_cfg.down.rca_tls_cert_file, 0, sizeof(g_cfg.down.rca_tls_cert_file));
        snprintf(g_cfg.down.rca_tls_cert_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 6: { // url
      if (g_cfg.op == kCRLReqOperationType_Download) {
        memset(g_cfg.down.req_url, 0, sizeof(g_cfg.down.req_url));
        snprintf(g_cfg.down.req_url, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 7: { // crl_file
      memset(g_cfg.crl_file, 0, sizeof(g_cfg.crl_file));
      snprintf(g_cfg.crl_file, MAXLINE, "%s", optarg);
      break;
    }
    case 8: { // libdbg
      g_cfg.lib_dbg = (unsigned int)strtoul(optarg, 0, 10);
      break;
    }
    default: {
      printf("Invalid option\n");
      ret = -1;
    }
  }
  return ret;
}


/**
 * @brief 유틸리티 실행 시 함께 입력된 파라미터들을 파싱하여 설정정보에 저장한다.
 * @param[in] argc 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 개수 (유틸리티 실행파일명 포함)
 * @param[in] argv 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (유틸리티 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int CRL_REQ_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
    {"rca",  required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
    {"ica",    required_argument, 0, 1},
    {"pca",    required_argument, 0, 2},
    {"ra",    required_argument, 0, 3},
    {"crlg",    required_argument, 0, 4},
    {"rca_tls",   required_argument, 0, 5},
    {"url", required_argument, 0, 6},
    {"crl_file", required_argument, 0, 7},
    {"libdbg", required_argument, 0, 8},
    {0, 0,                        0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 동작 유형을 설정하고 기본설정정보를 설정한다.
   */
  if (memcmp(argv[1], "down", 4) == 0) {
    g_cfg.op = kCRLReqOperationType_Download;
  } else if (memcmp(argv[1], "load", 4) == 0) {
    g_cfg.op = kCRLReqOperationType_Load;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }
  CRL_REQ_SetDefaultInputParameters(g_cfg.op);

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  while(1) {

    // 옵션 파싱
    c = getopt_long(argc, argv, "", options, &option_idx);
    if (c == -1) {  // 모든 파라미터 파싱 완료
      break;
    }

    // 파싱된 옵션 처리 -> 저장
    int ret = CRL_REQ_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 설정정보를 화면에 출력한다.
   */
  CRL_REQ_PrintCFG();

  return 0;
}

