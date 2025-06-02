/** 
  * @file 
  * @brief 식별인증서 발급 유틸리티 입력 파라미터 처리 기능 구현
  * @date 2022-07-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// 유틸리티 헤더 파일
#include "id-cert-req.h"


/**
 * @brief 입력 파라미터들에 대한 기본값을 설정한다.
 * @param[in] op 동작 유형
 */
static void ID_CERT_REQ_SetDefaultInputParameters(IdCertReqOperationType op)
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
  snprintf(g_cfg.ck_file, MAXLINE, "%s", g_default_verify_exp_key_file);
  snprintf(g_cfg.e_file, MAXLINE, "%s", g_default_cert_encryption_priv_key_file);
  snprintf(g_cfg.ek_file, MAXLINE, "%s", g_default_cert_encryption_exp_key_file);
  snprintf(g_cfg.req_h8_file, MAXLINE, "%s", g_default_id_cert_provisioning_req_h8_file);

  if (op == kIdCertReqOperationType_Req) {
    snprintf(g_cfg.req.provisiong_req_url, MAXLINE, "%s", g_default_id_cert_provisiong_req_url);
    snprintf(g_cfg.req.req_file, MAXLINE, "%s", g_default_id_cert_provisioning_req_file);
    snprintf(g_cfg.req.ack_file, MAXLINE, "%s", g_default_id_cert_provisioning_ack_file);
    snprintf(g_cfg.req.cert_dl_time_file, MAXLINE, "%s", g_default_cert_download_time_file);
  } else if (op == kIdCertReqOperationType_Down) {
    snprintf(g_cfg.down.download_req_url, MAXLINE, "%s", g_default_id_cert_download_req_url);
    g_cfg.down.target_time = g_default_target_time;
    snprintf(g_cfg.down.cmhf_dir, MAXLINE, "%s", g_default_id_cert_cmhf_dir);
    snprintf(g_cfg.down.cert_dir, MAXLINE, "%s", g_default_id_cert_dir);
    snprintf(g_cfg.down.tmp_zip_file, MAXLINE, "%s", g_default_tmp_zip_file_dir);
  } else if (op == kIdCertReqOperationType_Info) {
    snprintf(g_cfg.info.download_info_req_url, MAXLINE, "%s", g_default_id_cert_download_info_req_url);
  }
}


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int ID_CERT_REQ_ProcessParsedOption(int option)
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
    case 5: { // enroll
      memset(g_cfg.enroll_cmhf_dir, 0, sizeof(g_cfg.enroll_cmhf_dir));
      snprintf(g_cfg.enroll_cmhf_dir, MAXLINE, "%s", optarg);
      break;
    }
    case 6: { // url
      if (g_cfg.op == kIdCertReqOperationType_Req) {
        memset(g_cfg.req.provisiong_req_url, 0, sizeof(g_cfg.req.provisiong_req_url));
        snprintf(g_cfg.req.provisiong_req_url, MAXLINE, "%s", optarg);
      } else if (g_cfg.op == kIdCertReqOperationType_Down) {
        memset(g_cfg.down.download_req_url, 0, sizeof(g_cfg.down.download_req_url));
        snprintf(g_cfg.down.download_req_url, MAXLINE, "%s", optarg);
      } else if (g_cfg.op == kIdCertReqOperationType_Info) {
        memset(g_cfg.info.download_info_req_url, 0, sizeof(g_cfg.info.download_info_req_url));
        snprintf(g_cfg.info.download_info_req_url, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 7: { // rca_tls
      memset(g_cfg.rca_tls_cert_file, 0, sizeof(g_cfg.rca_tls_cert_file));
      snprintf(g_cfg.rca_tls_cert_file, MAXLINE, "%s", optarg);
      break;
    }
    case 8: { // v
      memset(g_cfg.v_file, 0, sizeof(g_cfg.v_file));
      snprintf(g_cfg.v_file, MAXLINE, "%s", optarg);
      break;
    }
    case 9: { // e
      memset(g_cfg.e_file, 0, sizeof(g_cfg.e_file));
      snprintf(g_cfg.e_file, MAXLINE, "%s", optarg);
      break;
    }
    case 10: { // h8
      memset(g_cfg.req_h8_file, 0, sizeof(g_cfg.req_h8_file));
      snprintf(g_cfg.req_h8_file, MAXLINE, "%s", optarg);
      break;
    }
    case 11: { // req
      if (g_cfg.op == kIdCertReqOperationType_Req) {
        memset(g_cfg.req.req_file, 0, sizeof(g_cfg.req.req_file));
        snprintf(g_cfg.req.req_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 12: { // ack
      if (g_cfg.op == kIdCertReqOperationType_Req) {
        memset(g_cfg.req.ack_file, 0, sizeof(g_cfg.req.ack_file));
        snprintf(g_cfg.req.ack_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 13: { // dltime
      if (g_cfg.op == kIdCertReqOperationType_Req) {
        memset(g_cfg.req.cert_dl_time_file, 0, sizeof(g_cfg.req.cert_dl_time_file));
        snprintf(g_cfg.req.cert_dl_time_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 14: { // cmhf
      if (g_cfg.op == kIdCertReqOperationType_Down) {
        memset(g_cfg.down.cmhf_dir, 0, sizeof(g_cfg.down.cmhf_dir));
        snprintf(g_cfg.down.cmhf_dir, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 15: { // cert
      if (g_cfg.op == kIdCertReqOperationType_Down) {
        memset(g_cfg.down.cert_dir, 0, sizeof(g_cfg.down.cert_dir));
        snprintf(g_cfg.down.cert_dir, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 16: { // zip
      if (g_cfg.op == kIdCertReqOperationType_Down) {
        memset(g_cfg.down.tmp_zip_file, 0, sizeof(g_cfg.down.tmp_zip_file));
        snprintf(g_cfg.down.tmp_zip_file, MAXLINE, "%s", optarg);
      }
      break;
    }
    case 17: { // ck
      memset(g_cfg.ck_file, 0, sizeof(g_cfg.ck_file));
      snprintf(g_cfg.ck_file, MAXLINE, "%s", optarg);
      break;
    }
    case 18: { // ek
      memset(g_cfg.ek_file, 0, sizeof(g_cfg.ek_file));
      snprintf(g_cfg.ek_file, MAXLINE, "%s", optarg);
      break;
    }
    case 19: { // t
      if (g_cfg.op == kIdCertReqOperationType_Down) {
        g_cfg.down.target_time = (Dot2IdCertTargetTime)strtoul(optarg, 0, 10);
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
int ID_CERT_REQ_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
  {"rca",  required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
  {"ica",    required_argument, 0, 1},
  {"pca",    required_argument, 0, 2},
  {"eca",    required_argument, 0, 3},
  {"ra",    required_argument, 0, 4},
  {"enroll",    required_argument, 0, 5},
  {"url", required_argument, 0, 6},
  {"rca_tls",   required_argument, 0, 7},
  {"v",    required_argument, 0, 8},
  {"e",     required_argument, 0, 9},
  {"h8",      required_argument, 0, 10},
  {"req",      required_argument, 0, 11},
  {"ack",      required_argument, 0, 12},
  {"dltime",    required_argument, 0, 13},
  {"cmhf",     required_argument, 0, 14},
  {"cert",    required_argument, 0, 15},
  {"zip",    required_argument, 0, 16},
  {"ck",    required_argument, 0, 17},
  {"ek",    required_argument, 0, 18},
  {"t",    required_argument, 0, 19},
  {"libdbg", required_argument, 0, 20},
  {0, 0,                        0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 동작 유형을 설정하고 기본설정정보를 설정한다.
   */
  if (!memcmp(argv[1], "req", 3)) {
    g_cfg.op = kIdCertReqOperationType_Req;
  } else if (!memcmp(argv[1], "down", 4)) {
    g_cfg.op = kIdCertReqOperationType_Down;
  } else if (!memcmp(argv[1], "info", 4)) {
    g_cfg.op = kIdCertReqOperationType_Info;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }
  ID_CERT_REQ_SetDefaultInputParameters(g_cfg.op);

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
    int ret = ID_CERT_REQ_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 설정정보를 화면에 출력한다.
   */
  ID_CERT_REQ_PrintCFG();

  return 0;
}

