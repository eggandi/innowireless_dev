/** 
  * @file 
  * @brief 부트스트래핑 유틸리티 메인 파일
  * @date 2022-07-17 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "bootstrap.h"


/*
 * 각 입력파라미터들의 기본값 (입력하지 않았을 경우에 적용되는 값)
 */
const char *g_default_cert_valid_duration = "6y";
const char *g_default_region = "410";  // CountryCode=410: 한국
const char *g_default_cert_psid = "32,35,135";
const char *g_default_rca_cert_file = "root.oer";
const char *g_default_ica_cert_file = "ICA.oer";
const char *g_default_pca_cert_file = "PCA.oer";
const char *g_default_eca_cert_file = "ECA.oer";
const char *g_default_ra_cert_file = "RA.oer";
const char *g_default_crlg_cert_file = "CRLG.oer";
const char *g_default_init_priv_key_file = "Initial.privkey";
const char *g_default_ecreq_file = "SignedEeEnrollmentCertRequest.oer";
const char *g_default_enroll_cert_file = "enrollment.oer";
const char *g_default_enroll_recon_priv_file = "enrollment.s";
const char *g_default_enroll_priv_key_file = "enrollment.privkey";
const char *g_default_lccf_file = "LCCF.oer";

struct BootstrapCFG g_cfg; ///< 부트스트래핑 설정정보


/**
 * @brief 유틸리티 프로그램 사용법을 출력한다.
 * @param[in] app_filename 프로그램 실행파일명
 */
static void BOOTSTRAP_Usage(const char *app_filename)
{
  printf("\n\n Description: Bootstrapping utility using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");

  printf("\n Usage: %s gen|proc [OPTIONS]\n\n", app_filename);
  printf("          gen: Generating ECRequest(enrollment certificate request)\n");
  printf("          proc: Processing ECResponse(enrollment certificate response)\n");

  printf("\n OPTIONS for \"gen\" operation\n");
  printf("  --start <yyyymmddhhmmss>   [INPUT]  Set enrollment cert valid start. If not specifed, set to current time\n");
  printf("  --dur <duration>           [INPUT]  Set enrollment cert valid duration, If not specified, set to %s\n", g_default_cert_valid_duration);
  printf("                                        duration example:\n");
  printf("                                          \"1000000s\" = 1000000 seconds\n");
  printf("                                          \"100000m\" = 10000 minutes\n");
  printf("                                          \"10000h\" = 1000 hours\n");
  printf("                                          \"1000x\" = 1000 sixty hours\n");
  printf("                                          \"100y\" = 100 years\n");
  printf("  --region <code1,cone2,...> [INPUT]  Set enrollment cert valid region(countryCode). If not specifed, set to %s\n", g_default_region);
  printf("  --psid <psid1,psid2,...>   [INPUT]  Set enrollment cert PSID. If not specified, set to %s\n", g_default_cert_psid);
  printf("  --req <file path>          [OUTPUT] Set OER-encoded ECResponse file path. If not specified, set to %s\n", g_default_ecreq_file);
  printf("  --ik <file path>           [OUTPUT] Set initial private key file path. If not specified, set to %s\n", g_default_init_priv_key_file);
  printf("  --libdbg <level>                    Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                          0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n OPTIONS for \"proc\" operation\n");
  printf("  --resp <file path>         [INPUT]  Set OER-encoded ECResponse file path. If not specified, not used\n");
  printf("  --ik <file path>           [INPUT]  Set initial private key file path. If not specified, set to %s\n", g_default_init_priv_key_file);
  printf("  --ec <file path>           [INPUT]  Set OER-encoded Enrollment cert file path, If not specified, set to %s\n", g_default_enroll_cert_file);
  printf("  --s <file path>            [INPUT]  Set private key reconstruction value file path. If not specified, set to %s\n", g_default_enroll_recon_priv_file);
  printf("  --rca <file path>          [INPUT]  Set OER-encoded RCA cert file path. If not specified, set to %s\n", g_default_rca_cert_file);;
  printf("  --eca <file path>          [INPUT]  Set OER-encoded ECA cert file path. If not specified, set to %s\n", g_default_eca_cert_file);
  printf("  --ra <file path>           [INPUT]  Set OER-encoded RA cert file path. If not specified, set to %s\n", g_default_ra_cert_file);
  printf("  --lccf <file path>         [INPUT]  Set OER-encoded LCCF file path. If not specified, set to %s\n", g_default_lccf_file);
  printf("  --ica <file path>          [OUTPUT] Set OER-encoded ICA cert file path. If not specified, set to %s\n", g_default_ica_cert_file);
  printf("  --pca <file path>          [OUTPUT] Set OER-encoded PCA cert file path. If not specified, set to %s\n", g_default_pca_cert_file);
  printf("  --crlg <file path>         [OUTPUT] Set OER-encoded CRLG cert file path. If not specified, set to %s\n", g_default_crlg_cert_file);
  printf("  --ek <file path>           [OUTPUT] Set (reconstructed) enrollment private key file path. If not specified, set to %s\n", g_default_enroll_priv_key_file);
  printf("  --libdbg <level>                    Set v2x libraries debug message print level. If not specified, set to %u\n", DEFAULT_LIB_DBG);
  printf("                                          0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n");

  printf("\n Example\n");
  printf("  1) %s gen\n", app_filename);
  printf("  2) %s gen --start 20220717113000 --dur 6y --region 180,181 --psid 32,38\n", app_filename);
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
    BOOTSTRAP_Usage(argv[0]);
    return 0;
  }

  printf("Running bootstrap utility\n");
  memset(&g_cfg, 0, sizeof(g_cfg));

  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  int ret = BOOTSTRAP_ParsingInputParameters(argc, argv);
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
   * 동작 유형에 따른 동작을 수행한다.
   */
  if (g_cfg.op == kBootstrapOperationType_Gen) {
    ret = BOOTSTRAP_GenerateECRequest();
  } else {
    ret = BOOTSTRAP_ProcessECResponse();
  }

  return 0;
}


/**
 * @brief Bootstrap 설정정보를 화면에 출력한다.
 */
void BOOTSTRAP_PrintBootstrapCFG(void)
{
  if (g_cfg.op == kBootstrapOperationType_Gen) {
    printf("Generation opeation CFG\n");
    printf("  [INPUT]  Enrollment cert valid start: %u\n", g_cfg.gen.valid_start);
    printf("  [INPUT]  Enrollment cert valid duration: %u", g_cfg.gen.dur);
    if (g_cfg.gen.dur_type == kDot2CertDurationType_Seconds) {
      printf(" seconds\n");
    } else if (g_cfg.gen.dur_type == kDot2CertDurationType_Minutes) {
      printf(" minutes\n");
    } else if (g_cfg.gen.dur_type == kDot2CertDurationType_Hours) {
      printf(" hours\n");
    } else if (g_cfg.gen.dur_type == kDot2CertDurationType_SixtyHours) {
      printf(" sixty hours\n");
    } else if (g_cfg.gen.dur_type == kDot2CertDurationType_Years) {
      printf(" years\n");
    }
    printf("  [INPUT]  Enrollment cert valid region: ");
    for (unsigned int i = 0; i < g_cfg.gen.region_num; i++) {
      printf("%u, ", g_cfg.gen.region[i]);
    }
    printf("\n");
    printf("  [INPUT]  Enrollment cert permissions(PSID): ");
    for (unsigned int i = 0; i < g_cfg.gen.psid_num; i++) {
      printf("%u, ", g_cfg.gen.psid[i]);
    }
    printf("\n");
    printf("  [OUTPUT] ECRequest file path: %s\n", g_cfg.gen.ecreq_file);
    printf("  [OUTPUT] Initial private key file path: %s\n", g_cfg.init_priv_key_file);
  } else {
    printf("Process operation CFG\n");
    if (g_cfg.proc.ecresp_file_present) {
      printf("  [INPUT]  ECResponse file path: %s\n", g_cfg.proc.ecresp_file);
    }
    printf("  [INPUT]  Initial private key file path: %s\n", g_cfg.init_priv_key_file);
    printf("  [INPUT]  Enrollment cert file path: %s\n", g_cfg.proc.enroll_cert_file);
    printf("  [INPUT]  Private key reconstrucation value file path: %s\n", g_cfg.proc.recon_priv_file);
    printf("  [INPUT]  RCA cert file path: %s\n", g_cfg.proc.rca_cert_file);
    printf("  [INPUT]  ECA cert file path: %s\n", g_cfg.proc.eca_cert_file);
    printf("  [INPUT]  RA cert file path: %s\n", g_cfg.proc.ra_cert_file);
    printf("  [INPUT]  LCCF file path: %s\n", g_cfg.proc.lccf_file);
    printf("  [OUTPUT] ICA cert file path: %s\n", g_cfg.proc.ica_cert_file);
    printf("  [OUTPUT] PCA cert file path: %s\n", g_cfg.proc.pca_cert_file);
    printf("  [OUTPUT] CRLG cert file path: %s\n", g_cfg.proc.crlg_cert_file);
    printf("  [OUTPUT] Enrollment private key file path: %s\n", g_cfg.proc.pca_cert_file);
  }
}


/**
 * @brief 바이트열을 HexString 형태로 화면에 출력한다.
 * @param[in] desc 바이트열 설명문
 * @param[in] octs 출력할 바이트열
 * @param[in] len 출력할 바이트열의 길이
 */
void BOOTSTRAP_PrintOcts(const char *desc, const uint8_t *octs, size_t len)
{
  printf("%s(%zu): ", desc, len);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(octs + i));
  }
  printf("\n");
}