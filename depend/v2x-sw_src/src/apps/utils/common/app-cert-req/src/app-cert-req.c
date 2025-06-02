/** 
  * @file 
  * @brief 응용인증서 발급요청/다운로드 유틸리티 메인 파일
  * @date 2022-07-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "app-cert-req.h"


/*
 * 각 입력파라미터들의 기본값 (입력하지 않았을 경우에 적용되는 값)
 */
const char *g_default_rca_cert_file = "root.oer";
const char *g_default_ica_cert_file = "ICA.oer";
const char *g_default_pca_cert_file = "PCA.oer";
const char *g_default_eca_cert_file = "ECA.oer";
const char *g_default_ra_cert_file = "RA.oer";
const char *g_default_crlg_cert_file = "CRLG.oer";
const char *g_default_enroll_cert_cmhf_dir = "./";
const char *g_default_app_cert_cmhf_dir = "./";
const char *g_default_app_cert_dir = "./";
const char *g_default_rca_tls_cert_file = "/etc/ssl/certs/bad7b270.0";
const char *g_default_verify_priv_key_file = "Initial.privkey";
const char *g_default_cert_encryption_priv_key_file = "CertEncryption.privkey";
const char *g_default_app_cert_provisioning_req_h8_file = "SecuredAppCertProvisioningRequest.oer.H8";
const char *g_default_app_cert_provisioning_req_file = "SecuredAppCertProvisioningRequest.oer";
const char *g_default_app_cert_provisioning_ack_file = "SignedAppCertProvisioningAck.oer";
const char *g_default_cert_download_time_file = "CertDownTime.txt";
const char *g_default_tmp_zip_file_dir = "./down.zip";
const char *g_default_app_cert_provisiong_req_url = "https://ra.scms.co.kr:8892/provision-application-certificate";
const char *g_default_app_cert_download_req_url = "https://ra.scms.co.kr:8892/download/application-certificate";
const char *g_default_lpf_download_url = "https://ra.scms.co.kr:8892/download/policy/local";
const char *g_default_lccf_download_url = "https://ra.scms.co.kr:8892/download/local-certificate-chain";

struct AppCertReqCFG g_cfg; ///< 유틸리티 설정정보


/**
 * @brief 유틸리티 프로그램 사용법을 출력한다.
 * @param[in] app_filename 프로그램 실행파일명
 */
static void APP_CERT_REQ_Usage(const char *app_filename)
{
  printf("\n\n Description: Application cert request utility using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s req|down|lpf|lccf [OPTIONS]\n\n", app_filename);
  printf("          req: Request application cert provisioning\n");
  printf("          down: Download application cert\n");
  printf("          lpf: Download LPF\n");
  printf("          lccf: Download LCCF\n");

  printf("\n OPTIONS for \"req\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --eca <file path>        [INPUT]  Set OER-encoded ECA cert file path. If not specified, set to \"%s\"\n", g_default_eca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --enroll <dir path>      [INPUT]  Set enrollment cert CMHF dir path, If not specified, set to \"%s\"\n", g_default_enroll_cert_cmhf_dir);
  printf("  --url <URL>              [INPUT]  Set URL for app cert provisiong request. If not specified, set to \"%s\"\n", g_default_app_cert_provisiong_req_url);
  printf("  --rca_tls <file path>    [INPUT]  Set RootCA TLS cert file path. If not specified, set to \"%s\"\n", g_default_rca_tls_cert_file);
  printf("  --v <file path>          [OUTPUT] Set private key file export path for verification. If not specified, set to \"%s\"\n", g_default_verify_priv_key_file);
  printf("  --e <file path>          [OUTPUT] Set private key file export path for cert encryption. If not specified, set to \"%s\"\n", g_default_cert_encryption_priv_key_file);
  printf("  --h8 <file path>         [OUTPUT] Set H8(SecuredAppCertProvisioningRequest) file export path. If not specified, set to \"%s\"\n", g_default_app_cert_provisioning_req_h8_file);
  printf("  --req <file path>        [OUTPUT] Set OER-encoded SecuredAppCertProvisioningRequest file export path. If not specified, set to \"%s\"\n", g_default_app_cert_provisioning_req_file);
  printf("  --ack <file path>        [OUTPUT] Set OER-encoded SignedAppCertProvisioningAck file export path. If not specified, set to \"%s\"\n", g_default_app_cert_provisioning_ack_file);
  printf("  --dltime <file path>     [OUTPUT] Set cert download time export file path. If not specified, set to \"%s\"\n", g_default_cert_download_time_file);
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"down\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --enroll <dir path>      [INPUT]  Set enrollment cert CMHF dir path, If not specified, set to \"%s\"\n", g_default_enroll_cert_cmhf_dir);
  printf("  --v <file path>          [INPUT]  Set private key file path for verification. If not specified, set to \"%s\"\n", g_default_verify_priv_key_file);
  printf("  --e <file path>          [INPUT]  Set private key file path for cert encryption. If not specified, set to \"%s\"\n", g_default_cert_encryption_priv_key_file);
  printf("  --h8 <file path>         [INPUT]  Set H8(SecuredAppCertProvisioningRequest) file path. If not specified, set to \"%s\"\n", g_default_app_cert_provisioning_req_h8_file);
  printf("  --url <URL>              [INPUT]  Set URL for app cert download request. If not specified, set to \"%s\"\n", g_default_app_cert_download_req_url);
  printf("  --cmhf <dir path>        [OUTPUT] Set app cert CMHF file export dir path. If not specified, set to \"%s\"\n", g_default_app_cert_cmhf_dir);
  printf("  --cert <dir path>        [OUTPUT] Set OER-encoded app cert/privkey/recon_priv file export dir path. If not specified, set to \"%s\"\n", g_default_app_cert_dir);
  printf("  --zip <file path>        [OUTPUT] Set temporary ZIP file(from server) file export path. If not specified, set to \"%s\"\n", g_default_tmp_zip_file_dir);
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"lpf\" operation\n");
  printf("  --url <URL>              [INPUT]  Set URL for LPF download. If not specified, set to \"%s\"\n", g_default_lpf_download_url);
  printf("  --rca_tls <file path>    [INPUT]  Set RootCA TLS cert file path. If not specified, set to \"%s\"\n", g_default_rca_tls_cert_file);
  printf("  --lpf <file name>        [INPUT]  Set LPF file name you already have. If not specified, not used\n");
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"lccf\" operation\n");
  printf("  --url <URL>              [INPUT]  Set URL for LCCF download. If not specified, set to \"%s\"\n", g_default_lccf_download_url);
  printf("  --rca_tls <file path>    [INPUT]  Set RootCA TLS cert file path. If not specified, set to \"%s\"\n", g_default_rca_tls_cert_file);
  printf("  --lccf <file name>       [INPUT]  Set LCCF file name you already have. If not specified, not used\n");
  printf("  --rca <file path>        [OUTPUT] Set OER-encoded RootCA cert file export path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [OUTPUT] Set OER-encoded ICA cert file export path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [OUTPUT] Set OER-encoded PCA/ACA cert file export path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --crlg <file path>       [OUTPUT] Set OER-encoded CRLG cert file export path. If not specified, set to \"%s\"\n", g_default_crlg_cert_file);
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s req\n", app_filename);
  printf("  2) %s down\n", app_filename);
  printf("  3) %s lpf\n", app_filename);
  printf("  4) %s lccf\n", app_filename);
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
    APP_CERT_REQ_Usage(argv[0]);
    return 0;
  }

  printf("Running application cert (for RSU) request utility\n");
  memset(&g_cfg, 0, sizeof(g_cfg));

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  int ret = APP_CERT_REQ_ParsingInputParameters(argc, argv);
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
  ret = APP_CERT_REQ_LoadSCCCertFiles();
  if (ret < 0) {
    return -1;
  }

  /*
   * 등록인증서 CMHF를 로딩한다.
   */
  ret = APP_CERT_REQ_LoadEnrollmentCMHFFile();
  if (ret < 0) {
    return -1;
  }

  /*
   * LCM 설정을 수행한다.
   */
  ret = APP_CERT_REQ_ConfigLCM();
  if (ret < 0) {
    return -1;
  }

  /*
   * 동작 유형에 따른 동작을 수행한다.
   */
  if (g_cfg.op == kAppCertReqOperationType_Req) {
    ret = APP_CERT_REQ_RequestAppCertProvisioning();
  } else if (g_cfg.op == kAppCertReqOperationType_Down) {
    ret = APP_CERT_REQ_DownloadAppCert();
  } else if (g_cfg.op == kAppCertReqOperationType_LPF) {
    ret = APP_CERT_REQ_DownloadLPF();
  } else {
    ret = APP_CERT_REQ_DownloadLCCF();
  }

  return 0;
}


/**
 * @brief 설정정보를 화면에 출력한다.
 */
void APP_CERT_REQ_PrintCFG(void)
{
  if (g_cfg.op == kAppCertReqOperationType_Req) {
    printf("Request opeation CFG\n");
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.rca_file);
    printf("  [INPUT]  ICA cert file path: %s\n", g_cfg.ica_file);
    printf("  [INPUT]  PCA cert file path: %s\n", g_cfg.pca_file);
    printf("  [INPUT]  ECA cert file path: %s\n", g_cfg.eca_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.ra_file);
    printf("  [INPUT]  Enrollmnet CMHF dir: %s\n", g_cfg.enroll_cmhf_dir);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.rca_tls_cert_file);
    printf("  [INPUT]  Provisioning request URL: %s\n", g_cfg.req.provisiong_req_url);
    printf("  [OUTPUT] Initial verification private key file export path: %s\n", g_cfg.v_file);
    printf("  [OUTPUT] Cert encryption private key file export path: %s\n", g_cfg.e_file);
    printf("  [OUTPUT] H8(SecuredAppCertProvisioningRequest) file export path: %s\n", g_cfg.req_h8_file);
    printf("  [OUTPUT] SecuredAppCertProvisioningRequest file export path: %s\n", g_cfg.req.req_file);
    printf("  [OUTPUT] SignedAppCertProvisioningAck file export path: %s\n", g_cfg.req.ack_file);
    printf("  [OUTPUT] Cert download time file path: %s\n", g_cfg.req.cert_dl_time_file);
  } else if (g_cfg.op == kAppCertReqOperationType_Down) {
    printf("Download operation CFG\n");
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.rca_file);
    printf("  [INPUT]  ICA cert file path: %s\n", g_cfg.ica_file);
    printf("  [INPUT]  PCA cert file path: %s\n", g_cfg.pca_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.ra_file);
    printf("  [INPUT]  Enrollmnet CMHF dir: %s\n", g_cfg.enroll_cmhf_dir);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.rca_tls_cert_file);
    printf("  [INPUT]  Initial verification private key file path: %s\n", g_cfg.v_file);
    printf("  [INPUT]  Cert ecryption private key file path: %s\n", g_cfg.e_file);
    printf("  [INPUT]  H8(SecuredAppCertProvisioningRequest) file path: %s\n", g_cfg.req_h8_file);
    printf("  [INPUT]  Download request URL: %s\n", g_cfg.down.download_req_url);
    printf("  [OUTPUT] App cert CMHF file export directory: %s\n", g_cfg.down.cmhf_dir);
    printf("  [OUTPUT] App cert file export directory: %s\n", g_cfg.down.cert_dir);
    printf("  [OUTPUT] Temp ZIP file export path: %s\n", g_cfg.down.tmp_zip_file);
  } else if (g_cfg.op == kAppCertReqOperationType_LPF) {
    printf("LPF operation CFG\n");
    printf("  [INPUT]  Server URL: %s\n", g_cfg.lpf.download_url);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.rca_tls_cert_file);
    if (g_cfg.lpf.current_filename_present) {
      printf("  [INPUT]  Current LPF filename: %s\n", g_cfg.lpf.current_filename);
    }
  } else { // LCCF
    printf("LCCF operation CFG\n");
    printf("  [INPUT]  Server URL: %s\n", g_cfg.lccf.download_url);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.rca_tls_cert_file);
    if (g_cfg.lccf.current_filename_present) {
      printf("  [INPUT]  Current LCCF filename: %s\n", g_cfg.lccf.current_filename);
    }
    printf("  [OUTPUT] RCA cert file export path: %s\n", g_cfg.rca_file);
    printf("  [OUTPUT] ICA cert file export path: %s\n", g_cfg.ica_file);
    printf("  [OUTPUT] PCA cert file export path: %s\n", g_cfg.pca_file);
    printf("  [OUTPUT] CRLG cert file export path: %s\n", g_cfg.lccf.crlg_file);
  }
}


/**
 * @brief LCM 설정을 수행한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int APP_CERT_REQ_ConfigLCM(void)
{
  /*
   * RootCA TLS 인증서 파일 경로를 설정한다.
   */
  int ret = Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_cfg.rca_tls_cert_file);
  if (ret < 0) {
    return -1;
  }

  /*
   * 응용인증서 발급요청 URL을 설정한다.
   */
  if (g_cfg.op == kAppCertReqOperationType_Req) {
    ret = Dot2_ConfigLCM(kDot2LCMConfigType_AppCertProvisioningReqURL, g_cfg.req.provisiong_req_url);
    if (ret < 0) {
      return -1;
    }
  }

  /*
   * LPF 다운로드 URL을 설정한다.
   */
  if (g_cfg.op == kAppCertReqOperationType_LPF) {
    ret = Dot2_ConfigLCM(kDot2LCMConfigType_LPFReqURL, g_cfg.lpf.download_url);
    if (ret < 0) {
      return -1;
    }
  }

  /*
   * LCCF 다운로드 URL을 설정한다.
   */
  if (g_cfg.op == kAppCertReqOperationType_LCCF) {
    ret = Dot2_ConfigLCM(kDot2LCMConfigType_LCCFReqURL, g_cfg.lccf.download_url);
    if (ret < 0) {
      return -1;
    }
  }

  /*
   * ZIP 파일 임시저장 디렉토리를 설정한다.
   */
  if (g_cfg.op == kAppCertReqOperationType_Down) {
    ret = Dot2_ConfigLCM(kDot2LCMConfigType_TmpZipFilePath, g_cfg.down.tmp_zip_file);
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
void APP_CERT_REQ_PrintOcts(const char *desc, const uint8_t *octs, size_t len)
{
  printf("%s(%zu): ", desc, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(octs + i));
  }
  printf("\n");
}