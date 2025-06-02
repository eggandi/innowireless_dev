/** 
  * @file 
  * @brief 식별인증서 발급요청/다운로드 유틸리티 메인 파일
  * @date 2022-07-28 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "id-cert-req.h"


/*
 * 각 입력파라미터들의 기본값 (입력하지 않았을 경우에 적용되는 값)
 */
const char *g_default_rca_cert_file = "root.oer";
const char *g_default_ica_cert_file = "ICA.oer";
const char *g_default_pca_cert_file = "PCA.oer";
const char *g_default_eca_cert_file = "ECA.oer";
const char *g_default_ra_cert_file = "RA.oer";
const char *g_default_enroll_cert_cmhf_dir = "./";
const char *g_default_id_cert_cmhf_dir = "./";
const char *g_default_id_cert_dir = "./";
const char *g_default_rca_tls_cert_file = "/etc/ssl/certs/bad7b270.0";
const char *g_default_verify_priv_key_file = "Initial.privkey";
const char *g_default_verify_exp_key_file = "Initial.expkey";
const char *g_default_cert_encryption_priv_key_file = "CertEncryption.privkey";
const char *g_default_cert_encryption_exp_key_file = "CertEncryption.expkey";
const char *g_default_id_cert_provisioning_req_h8_file = "SecuredIdCertProvisioningRequest.oer.H8";
const char *g_default_id_cert_provisioning_req_file = "SecuredIdCertProvisioningRequest.oer";
const char *g_default_id_cert_provisioning_ack_file = "SignedIdCertProvisioningAck.oer";
const char *g_default_cert_download_time_file = "CertDownTime.txt";
const char *g_default_tmp_zip_file_dir = "./down.zip";
Dot2IdCertTargetTime g_default_target_time = Dot2IdCertTargetTime_Current;
const char *g_default_id_cert_provisiong_req_url = "https://ra.scms.co.kr:8892/provision-identity-certificate";
const char *g_default_id_cert_download_req_url = "https://ra.scms.co.kr:8892/download/identity-certificate";
const char *g_default_id_cert_download_info_req_url = "https://ra.scms.co.kr:8892/download/info";

struct IdCertReqCFG g_cfg; ///< 유틸리티 설정정보


/**
 * @brief 유틸리티 프로그램 사용법을 출력한다.
 * @param[in] app_filename 프로그램 실행파일명
 */
static void ID_CERT_REQ_Usage(const char *app_filename)
{
  printf("\n\n Description: Id cert request utility using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s req|down|info [OPTIONS]\n\n", app_filename);
  printf("          req: Request id cert provisioning\n");
  printf("          down: Download id certs (1 set(=20 certs) for 1 weeks)\n");
  printf("          info: Download id cert donwload info (possible time to download next duration certs)\n");

  printf("\n OPTIONS for \"req\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --eca <file path>        [INPUT]  Set OER-encoded ECA cert file path. If not specified, set to \"%s\"\n", g_default_eca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --enroll <dir path>      [INPUT]  Set enrollment cert CMHF dir path, If not specified, set to \"%s\"\n", g_default_enroll_cert_cmhf_dir);
  printf("  --url <URL>              [INPUT]  Set URL for id cert provisiong request. If not specified, set to \"%s\"\n", g_default_id_cert_provisiong_req_url);
  printf("  --rca_tls <file path>    [INPUT]  Set RootCA TLS cert file path. If not specified, set to \"%s\"\n", g_default_rca_tls_cert_file);
  printf("  --v <file path>          [OUTPUT] Set private key file export path for verification. If not specified, set to \"%s\"\n", g_default_verify_priv_key_file);
  printf("  --ck <file path>         [OUTPUT] Set expansion key file export path for verification. If not specified, set to \"%s\"\n", g_default_verify_exp_key_file);
  printf("  --e <file path>          [OUTPUT] Set private key file export path for cert encryption. If not specified, set to \"%s\"\n", g_default_cert_encryption_priv_key_file);
  printf("  --ek <file path>         [OUTPUT] Set expansion key file export path for cert encryption. If not specified, set to \"%s\"\n", g_default_cert_encryption_priv_key_file);
  printf("  --h8 <file path>         [OUTPUT] Set H8(SecuredIdCertProvisioningRequest) file export path. If not specified, set to \"%s\"\n", g_default_id_cert_provisioning_req_h8_file);
  printf("  --req <file path>        [OUTPUT] Set OER-encoded SecuredIdCertProvisioningRequest file export path. If not specified, set to \"%s\"\n", g_default_id_cert_provisioning_req_file);
  printf("  --ack <file path>        [OUTPUT] Set OER-encoded SignedIdCertProvisioningAck file export path. If not specified, set to \"%s\"\n", g_default_id_cert_provisioning_ack_file);
  printf("  --dltime <file path>     [OUTPUT] Set cert download time file export path. If not specified, set to \"%s\"\n", g_default_cert_download_time_file);
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"down\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --enroll <dir path>      [INPUT]  Set enrollment cert CMHF dir path, If not specified, set to \"%s\"\n", g_default_enroll_cert_cmhf_dir);
  printf("  --v <file path>          [INPUT]  Set private key file path for verification. If not specified, set to \"%s\"\n", g_default_verify_priv_key_file);
  printf("  --ck <file path>         [INPUT]  Set expansion key file path for verification. If not specified, set to \"%s\"\n", g_default_verify_exp_key_file);
  printf("  --e <file path>          [INPUT]  Set private key file path for cert encryption. If not specified, set to \"%s\"\n", g_default_cert_encryption_priv_key_file);
  printf("  --ek <file path>         [INPUT]  Set expansion key file path for cert encryption. If not specified, set to \"%s\"\n", g_default_cert_encryption_exp_key_file);
  printf("  --h8 <file path>         [INPUT]  Set H8(SecuredIdCertProvisioningRequest) file export path. If not specified, set to \"%s\"\n", g_default_id_cert_provisioning_req_h8_file);
  printf("  --url <URL>              [INPUT]  Set URL for id cert download request. If not specified, set to \"%s\"\n", g_default_id_cert_download_req_url);
  printf("  --t <dec value>          [INPUT]  Set target time. If not specified, set to %u\n", g_default_target_time);
  printf("  --cmhf <dir path>        [OUTPUT] Set id cert CMHF file export dir path. If not specified, set to \"%s\"\n", g_default_id_cert_cmhf_dir);
  printf("  --cert <dir path>        [OUTPUT] Set OER-encoded id cert/privkey/recon_priv file export dir path. If not specified, set to \"%s\"\n", g_default_id_cert_dir);
  printf("  --zip <file path>        [OUTPUT] Set temporary ZIP file(from server) export file path. If not specified, set to \"%s\"\n", g_default_tmp_zip_file_dir);
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"info\" operation\n");
  printf("  --rca <file path>        [INPUT]  Set OER-encoded RootCA cert file path. If not specified, set to \"%s\"\n", g_default_rca_cert_file);
  printf("  --ica <file path>        [INPUT]  Set OER-encoded ICA cert file path. If not specified, set to \"%s\"\n", g_default_ica_cert_file);
  printf("  --pca <file path>        [INPUT]  Set OER-encoded PCA/ACA cert file path. If not specified, set to \"%s\"\n", g_default_pca_cert_file);
  printf("  --ra <file path>         [INPUT]  Set OER-encoded RA cert file path. If not specified, set to \"%s\"\n", g_default_ra_cert_file);
  printf("  --enroll <dir path>      [INPUT]  Set enrollment cert CMHF dir path, If not specified, set to \"%s\"\n", g_default_enroll_cert_cmhf_dir);
  printf("  --h8 <file path>         [INPUT]  Set H8(SecuredIdCertProvisioningRequest) file export path. If not specified, set to \"%s\"\n", g_default_id_cert_provisioning_req_h8_file);
  printf("  --url <URL>              [INPUT]  Set URL for id cert download info request. If not specified, set to \"%s\"\n", g_default_id_cert_download_info_req_url);
  printf("  --libdbg <level>                  Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                        0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s req\n", app_filename);
  printf("  2) %s down\n", app_filename);
  printf("  3) %s info\n", app_filename);
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
    ID_CERT_REQ_Usage(argv[0]);
    return 0;
  }

  printf("Running id cert (for OBU) request utility\n");
  memset(&g_cfg, 0, sizeof(g_cfg));

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  int ret = ID_CERT_REQ_ParsingInputParameters(argc, argv);
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
  ret = ID_CERT_REQ_LoadSCCCertFiles();
  if (ret < 0) {
    return -1;
  }

  /*
   * 등록인증서 CMHF를 로딩한다.
   */
  ret = ID_CERT_REQ_LoadEnrollmentCMHFFile();
  if (ret < 0) {
    return -1;
  }

  /*
   * LCM 설정을 수행한다.
   */
  ret = ID_CERT_REQ_ConfigLCM();
  if (ret < 0) {
    return -1;
  }

  /*
   * 동작 유형에 따른 동작을 수행한다.
   */
  if (g_cfg.op == kIdCertReqOperationType_Req) {
    ret = ID_CERT_REQ_RequestIdCertProvisioning();
  } else if (g_cfg.op == kIdCertReqOperationType_Down) {
    ret = ID_CERT_REQ_DownloadIdCert();
  } else if (g_cfg.op == kIdCertReqOperationType_Info) {
    ret = ID_CERT_REQ_DownloadIdCertDownloadInfo();
  }

  return 0;
}


/**
 * @brief 설정정보를 화면에 출력한다.
 */
void ID_CERT_REQ_PrintCFG(void)
{
  if (g_cfg.op == kIdCertReqOperationType_Req) {
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
    printf("  [OUTPUT] Verification expansion key file export path: %s\n", g_cfg.ck_file);
    printf("  [OUTPUT] Cert encryption private key file export path: %s\n", g_cfg.e_file);
    printf("  [OUTPUT] Cert encryption expansion key file export path: %s\n", g_cfg.ek_file);
    printf("  [OUTPUT] H8(SecuredIdCertProvisioningRequest) file export path: %s\n", g_cfg.req_h8_file);
    printf("  [OUTPUT] SecuredIdCertProvisioningRequest file export path: %s\n", g_cfg.req.req_file);
    printf("  [OUTPUT] SignedIdCertProvisioningAck file export path: %s\n", g_cfg.req.ack_file);
    printf("  [OUTPUT] Cert download time file export path: %s\n", g_cfg.req.cert_dl_time_file);
  } else if (g_cfg.op == kIdCertReqOperationType_Down) {
    printf("Download operation CFG\n");
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.rca_file);
    printf("  [INPUT]  ICA cert file path: %s\n", g_cfg.ica_file);
    printf("  [INPUT]  PCA cert file path: %s\n", g_cfg.pca_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.ra_file);
    printf("  [INPUT]  Enrollmnet CMHF dir: %s\n", g_cfg.enroll_cmhf_dir);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.rca_tls_cert_file);
    printf("  [INPUT]  Initial verification private key file path: %s\n", g_cfg.v_file);
    printf("  [INPUT]  Verification expansion key file path: %s\n", g_cfg.ck_file);
    printf("  [INPUT]  Cert ecryption private key file path: %s\n", g_cfg.e_file);
    printf("  [INPUT]  Cert ecryption expansion key file path: %s\n", g_cfg.ek_file);
    printf("  [INPUT]  H8(SecuredIdCertProvisioningRequest) file path: %s\n", g_cfg.req_h8_file);
    printf("  [INPUT]  Download request URL: %s\n", g_cfg.down.download_req_url);
    printf("  [INPUT]  Target time: %u\n", g_cfg.down.target_time);
    printf("  [OUTPUT] Id cert CMHF directory: %s\n", g_cfg.down.cmhf_dir);
    printf("  [OUTPUT] Id cert directory: %s\n", g_cfg.down.cert_dir);
    printf("  [OUTPUT] Temp ZIP file path: %s\n", g_cfg.down.tmp_zip_file);
  } else if (g_cfg.op == kIdCertReqOperationType_Info) {
    printf("Download operation CFG\n");
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.rca_file);
    printf("  [INPUT]  ICA cert file path: %s\n", g_cfg.ica_file);
    printf("  [INPUT]  PCA cert file path: %s\n", g_cfg.pca_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.ra_file);
    printf("  [INPUT]  Enrollmnet CMHF dir: %s\n", g_cfg.enroll_cmhf_dir);
    printf("  [INPUT]  RCA TLS cert file path: %s\n", g_cfg.rca_tls_cert_file);
    printf("  [INPUT]  H8(SecuredIdCertProvisioningRequest) file path: %s\n", g_cfg.req_h8_file);
    printf("  [INPUT]  Download info request URL: %s\n", g_cfg.info.download_info_req_url);
  }
}


/**
 * @brief LCM 설정을 수행한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int ID_CERT_REQ_ConfigLCM(void)
{
  /*
   * RootCA TLS 인증서 파일 경로를 설정한다.
   */
  int ret = Dot2_ConfigLCM(kDot2LCMConfigType_RCATLSCertFilePath, g_cfg.rca_tls_cert_file);
  if (ret < 0) {
    return -1;
  }

  /*
   * 식별인증서 발급요청 URL을 설정한다.
   */
  if (g_cfg.op == kIdCertReqOperationType_Req) {
    ret = Dot2_ConfigLCM(kDot2LCMConfigType_IdCertProvisioningReqURL, g_cfg.req.provisiong_req_url);
    if (ret < 0) {
      return -1;
    }
  }

  /*
   * ZIP 파일 임시저장 디렉토리를 설정한다.
   */
  if (g_cfg.op == kIdCertReqOperationType_Down) {
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
void ID_CERT_REQ_PrintOcts(const char *desc, const uint8_t *octs, size_t len)
{
  printf("%s(%zu): ", desc, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(octs + i));
  }
  printf("\n");
}