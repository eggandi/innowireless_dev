/** 
  * @file 
  * @brief 응용인증서 발급 유틸리티 입력 파라미터 처리 기능 구현
  * @date 2022-07-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// 유틸리티 헤더 파일
#include "app-cert-req.h"


/**
 * @brief 입력 파라미터들에 대한 기본값을 설정한다.
 * @param[in] op 동작 유형
 */
static void APP_CERT_REQ_SetDefaultInputParameters(AppCertReqOperationType op)
{
  g_cfg.lib_dbg = DEFAULT_LIB_DBG;
  snprintf(g_cfg.rca_file, MAXLINE, "%s", g_default_rca_cert_file);
  snprintf(g_cfg.ica_file, MAXLINE, "%s", g_default_ica_cert_file);
  snprintf(g_cfg.pca_file, MAXLINE, "%s", g_default_pca_cert_file);
  snprintf(g_cfg.eca_file, MAXLINE, "%s", g_default_eca_cert_file);
  snprintf(g_cfg.ra_file, MAXLINE, "%s", g_default_ra_cert_file);
  snprintf(g_cfg.enroll_cmhf_dir, MAXLINE, "%s", g_default_enroll_cert_cmhf_dir);
  snprintf(g_cfg.rca_tls_cert_file, MAXLINE, "%s", g_default_rca_tls_cert_file);
  snprintf(g_cfg.v_file, MAXLINE, "%s", g_default_verify_priv_key_file);
  snprintf(g_cfg.e_file, MAXLINE, "%s", g_default_cert_encryption_priv_key_file);
  snprintf(g_cfg.req_h8_file, MAXLINE, "%s", g_default_app_cert_provisioning_req_h8_file);

  if (op == kAppCertReqOperationType_Req) {
    snprintf(g_cfg.req.provisiong_req_url, MAXLINE, "%s", g_default_app_cert_provisiong_req_url);
    snprintf(g_cfg.req.cert_dl_time_file, MAXLINE, "%s", g_default_cert_download_time_file);
    snprintf(g_cfg.req.req_file, MAXLINE, "%s", g_default_app_cert_provisioning_req_file);
    snprintf(g_cfg.req.ack_file, MAXLINE, "%s", g_default_app_cert_provisioning_ack_file);
  } else if (op == kAppCertReqOperationType_Down) {
    snprintf(g_cfg.down.download_req_url, MAXLINE, "%s", g_default_app_cert_download_req_url);
    snprintf(g_cfg.down.cmhf_dir, MAXLINE, "%s", g_default_app_cert_cmhf_dir);
    snprintf(g_cfg.down.cert_dir, MAXLINE, "%s", g_default_app_cert_dir);
    snprintf(g_cfg.down.tmp_zip_file, MAXLINE, "%s", g_default_tmp_zip_file_dir);
  } else if (op == kAppCertReqOperationType_LPF) {
    snprintf(g_cfg.lpf.download_url, MAXLINE, "%s", g_default_lpf_download_url);
    g_cfg.lpf.current_filename_present = false;
  } else { // lccf
    snprintf(g_cfg.lccf.download_url, MAXLINE, "%s", g_default_lccf_download_url);
    snprintf(g_cfg.lccf.crlg_file, MAXLINE, "%s", g_default_crlg_cert_file);
    g_cfg.lccf.current_filename_present = false;
  }
}


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int APP_CERT_REQ_ProcessParsedOption(int option)
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
    case 3: { // "eca"
      memset(g_cfg.eca_file, 0, sizeof(g_cfg.eca_file));
      snprintf(g_cfg.eca_file, MAXLINE, "%s", optarg);
      break;
    }
    case 4: { // "ra"
      memset(g_cfg.ra_file, 0, sizeof(g_cfg.ra_file));
      snprintf(g_cfg.ra_file, MAXLINE, "%s", optarg);
      break;
    }
    case 5: { // "crlg"
      if (g_cfg.op == kAppCertReqOperationType_LCCF) {
        memset(g_cfg.lccf.crlg_file, 0, sizeof(g_cfg.lccf.crlg_file));
        snprintf(g_cfg.lccf.crlg_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 6: { // enroll
      memset(g_cfg.enroll_cmhf_dir, 0, sizeof(g_cfg.enroll_cmhf_dir));
      snprintf(g_cfg.enroll_cmhf_dir, MAXLINE, "%s", optarg);
      break;
    }
    case 7: { // url
      if (g_cfg.op == kAppCertReqOperationType_Req) {
        memset(g_cfg.req.provisiong_req_url, 0, sizeof(g_cfg.req.provisiong_req_url));
        snprintf(g_cfg.req.provisiong_req_url, MAXLINE, "%s", optarg);
      } else if (g_cfg.op == kAppCertReqOperationType_Down) {
        memset(g_cfg.down.download_req_url, 0, sizeof(g_cfg.down.download_req_url));
        snprintf(g_cfg.down.download_req_url, MAXLINE, "%s", optarg);
      } else if (g_cfg.op == kAppCertReqOperationType_LPF) {
        memset(g_cfg.lpf.download_url, 0, sizeof(g_cfg.lpf.download_url));
        snprintf(g_cfg.lpf.download_url, MAXLINE, "%s", optarg);
      } else { // lccf
        memset(g_cfg.lccf.download_url, 0, sizeof(g_cfg.lccf.download_url));
        snprintf(g_cfg.lccf.download_url, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 8: { // rca_tls
      memset(g_cfg.rca_tls_cert_file, 0, sizeof(g_cfg.rca_tls_cert_file));
      snprintf(g_cfg.rca_tls_cert_file, MAXLINE, "%s", optarg);
      break;
    }
    case 9: { // v
      memset(g_cfg.v_file, 0, sizeof(g_cfg.v_file));
      snprintf(g_cfg.v_file, MAXLINE, "%s", optarg);
      break;
    }
    case 10: { // e
      memset(g_cfg.e_file, 0, sizeof(g_cfg.e_file));
      snprintf(g_cfg.e_file, MAXLINE, "%s", optarg);
      break;
    }
    case 11: { // h8
      memset(g_cfg.req_h8_file, 0, sizeof(g_cfg.req_h8_file));
      snprintf(g_cfg.req_h8_file, MAXLINE, "%s", optarg);
      break;
    }
    case 12: { // req
      if (g_cfg.op == kAppCertReqOperationType_Req) {
        memset(g_cfg.req.req_file, 0, sizeof(g_cfg.req.req_file));
        snprintf(g_cfg.req.req_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 13: { // ack
      if (g_cfg.op == kAppCertReqOperationType_Req) {
        memset(g_cfg.req.ack_file, 0, sizeof(g_cfg.req.ack_file));
        snprintf(g_cfg.req.ack_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 14: { // dltime
      if (g_cfg.op == kAppCertReqOperationType_Req) {
        memset(g_cfg.req.cert_dl_time_file, 0, sizeof(g_cfg.req.cert_dl_time_file));
        snprintf(g_cfg.req.cert_dl_time_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 15: { // cmhf
      if (g_cfg.op == kAppCertReqOperationType_Down) {
        memset(g_cfg.down.cmhf_dir, 0, sizeof(g_cfg.down.cmhf_dir));
        snprintf(g_cfg.down.cmhf_dir, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 16: { // cert
      if (g_cfg.op == kAppCertReqOperationType_Down) {
        memset(g_cfg.down.cert_dir, 0, sizeof(g_cfg.down.cert_dir));
        snprintf(g_cfg.down.cert_dir, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 17: { // lpf
      if (g_cfg.op == kAppCertReqOperationType_LPF) {
        memset(g_cfg.lpf.current_filename, 0, sizeof(g_cfg.lpf.current_filename));
        snprintf(g_cfg.lpf.current_filename, MAXLINE, "%s", optarg);
        g_cfg.lpf.current_filename_present = true;
      }
      break;
    }
    case 18: { // lccf
      if (g_cfg.op == kAppCertReqOperationType_LCCF) {
        memset(g_cfg.lccf.current_filename, 0, sizeof(g_cfg.lccf.current_filename));
        snprintf(g_cfg.lccf.current_filename, MAXLINE, "%s", optarg);
        g_cfg.lccf.current_filename_present = true;
      }
      break;
    }
    case 19: { // zip
      if (g_cfg.op == kAppCertReqOperationType_Down) {
        memset(g_cfg.down.tmp_zip_file, 0, sizeof(g_cfg.down.tmp_zip_file));
        snprintf(g_cfg.down.tmp_zip_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 20: { // libdbg
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
int APP_CERT_REQ_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
  {"rca",  required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
  {"ica",    required_argument, 0, 1},
  {"pca",    required_argument, 0, 2},
  {"eca",    required_argument, 0, 3},
  {"ra",    required_argument, 0, 4},
  {"crlg",    required_argument, 0, 5},
  {"enroll",    required_argument, 0, 6},
  {"url", required_argument, 0, 7},
  {"rca_tls",   required_argument, 0, 8},
  {"v",    required_argument, 0, 9},
  {"e",     required_argument, 0, 10},
  {"h8",      required_argument, 0, 11},
  {"req",      required_argument, 0, 12},
  {"ack",      required_argument, 0, 13},
  {"dltime",    required_argument, 0, 14},
  {"cmhf",     required_argument, 0, 15},
  {"cert",    required_argument, 0, 16},
  {"lpf",    required_argument, 0, 17},
  {"lccf",    required_argument, 0, 18},
  {"zip",    required_argument, 0, 19},
  {"libdbg", required_argument, 0, 20},
  {0, 0,                        0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 동작 유형을 설정하고 기본설정정보를 설정한다.
   */
  if (!memcmp(argv[1], "req", 3)) {
    g_cfg.op = kAppCertReqOperationType_Req;
  } else if (!memcmp(argv[1], "down", 4)) {
    g_cfg.op = kAppCertReqOperationType_Down;
  } else if (!memcmp(argv[1], "lpf", 3)) {
    g_cfg.op = kAppCertReqOperationType_LPF;
  } else if (!memcmp(argv[1], "lccf", 4)) {
    g_cfg.op = kAppCertReqOperationType_LCCF;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }
  APP_CERT_REQ_SetDefaultInputParameters(g_cfg.op);

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
    int ret = APP_CERT_REQ_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 설정정보를 화면에 출력한다.
   */
  APP_CERT_REQ_PrintCFG();

  return 0;
}

