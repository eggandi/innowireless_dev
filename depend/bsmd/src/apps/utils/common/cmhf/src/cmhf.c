/** 
 * @file
 * @brief cmhf 유틸리티 구현 메인 파일
 * @date 2020-05-23
 * @author gyun
 *
 * 본 유틸리티는 Implicit 인증서, 상위인증서, 개인키재구성값 등을 이용하여 CMHF 파일을 생성한다. \n
 * 본 유틸리티는 dot2 라이브러리 API를 사용한다.
 */


// 시스템 헤더 파일
#include <stdio.h>
#include <string.h>

// 유틸리티 내부 헤더 파일
#include "cmhf.h"


/// 유틸리티 동작 유형
CMHFOperationType g_op;
/// 디버그 메시지 출력 여부
bool g_dbg = false;

/// cmhf 파일 저장 경로
char g_cmhf_file_path[MAXLINE];
// 상위인증서 파일경로
char g_issuer_file_path[MAXLINE];
/// 내 인증서 파일 경로
char g_my_cert_file_path[MAXLINE];
/// 개인키 재구성값 파일 경로
char g_recon_priv_file_path[MAXLINE];
/// 초기개인키 파일 경로 (응용인증서인 경우)
char g_init_priv_file_path[MAXLINE];
/// 내 인증서들이 위치한 디렉토리명 (익명/식별 인증서인 경우)
char g_my_certs_dir[MAXLINE];
/// 시드개인키 파일 경로 (익명/식별 인증서인 경우)
char g_seed_priv_file_path[MAXLINE];
/// 키 확장 키 파일 경로 (익명/식별 인증서인 경우)
char g_exp_key_file_path[MAXLINE];
/// 상위인증서 데이터가 저장되는 버퍼
uint8_t g_issuer[kDot2CertSize_Max];
/// 상위인증서의 크기
size_t g_issuer_size;
/// 내 인증서 데이터가 저장되는 버퍼
uint8_t g_my_cert[kDot2CertSize_Max];
/// 내 인증서의 크기
size_t g_my_cert_size;
/// 개인키 재구성값이 저장되는 버퍼
uint8_t g_recon_priv[DOT2_EC_256_KEY_LEN];
/// 인증서요청 초기개인키가 저장되는 버퍼 (응용인증서인 경우)
uint8_t g_init_priv[DOT2_EC_256_KEY_LEN];
/// 키 확장용 키가 저장되는 버퍼 (익명/식별 인증서인 경우)
uint8_t g_exp_key[DOT2_AES_128_LEN];
/// 시드개인키가 저장되는 버퍼 (익명/식별 인증서인 경우)
uint8_t g_seed_priv[DOT2_EC_256_KEY_LEN];


/**
 * @brief 유틸리티 프로그램 사용법을 출력한다.
 * @param[in] file_name 프로그램 실행파일명
 */
static void CMHF_Usage(const char *file_name)
{
  printf("\nUsage:\n");

  printf("  Make APPLICATION cert cmhf file    :   %s a <issuer cert file path> "
         "<app cert file path> <recon_priv file path> <init_priv_key file path> [dbg - on|off]\n", file_name);
  printf("  Make PSEUDONYM cert cmhf file      :   %s p <issuer cert file path> "
         "<psedonym cert files directory> <seed_priv file path> <exp_key file path> [dbg - on|off]\n", file_name);
  printf("  Make IDENTIFICATION cert cmhf file :   %s i <issuer cert file path> "
         "<psedonym cert files directory> <seed_priv file path> <exp_key file path> [dbg - on|off]\n", file_name);

  printf("\nExamples:\n");
  printf("  Make application cert cmhf file    :   %s a trustedcerts/pca downloadFiles/b68ce89c75396849.cert "
         "downloadFile/b68ce89c75396849.s dwnl_sgn.priv\n", file_name);
  printf("  Make pseudonym cert cmhf file      :   %s p trustedcerts/pca download/10a/ dwnl_sgn.priv sgn_expnsn.key\n", file_name);
  printf("  Make identifcation cert cmhf file  :   %s i trustedcerts/pca download/10a/ dwnl_sgn.priv sgn_expnsn.key\n", file_name);
  printf("\n");
}


/**
 * @brief 문자열을 복사한다.
 * @param dst 문자열이 복사될 버퍼
 * @param src 복사할 분자열
 * @param dst_size dst 버퍼의 크기
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int CMHF_CopyString(char *dst, const char *src, size_t dst_size)
{
  if (strlen(src) > dst_size) {
    return -1;
  }
  memcpy(dst, src, strlen(src));
  return 0;
}


/**
 * @brief 프로그램 입력 파라미터를 파싱하여 저장한다.
 * @param[in] argc 입력된 실행파라미터 개수
 * @param[in] argv 입력된 실행파라미터(들)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int CMHF_ParseInputParameters(int argc, const char *argv[])
{
  /*
   * 입력 파라미터 저장 변수를 초기화한다.
   */
  memset(g_cmhf_file_path, 0, sizeof(g_cmhf_file_path));
  memset(g_issuer_file_path, 0, sizeof(g_issuer_file_path));
  memset(g_my_cert_file_path, 0, sizeof(g_my_cert_file_path));
  memset(g_recon_priv_file_path, 0, sizeof(g_recon_priv_file_path));
  memset(g_init_priv_file_path, 0, sizeof(g_init_priv_file_path));
  memset(g_my_certs_dir, 0, sizeof(g_my_certs_dir));
  memset(g_seed_priv_file_path, 0, sizeof(g_seed_priv_file_path));
  memset(g_exp_key_file_path, 0, sizeof(g_exp_key_file_path));
  memset(g_issuer, 0, sizeof(g_issuer));
  memset(g_my_cert, 0, sizeof(g_my_cert));
  memset(g_recon_priv, 0, sizeof(g_recon_priv));
  memset(g_init_priv, 0, sizeof(g_init_priv));
  memset(g_exp_key, 0, sizeof(g_exp_key));
  memset(g_seed_priv, 0, sizeof(g_seed_priv));
  g_issuer_size = 0;
  g_my_cert_size = 0;

  /*
   * 실행파일명 외에 입력 파라미터가 없으면 실패를 반환한다.
   */
  if (argc < 2) {
    return -1;
  }

  // 응용 인증서 관련 cmhf 생성
  if (strncmp(argv[1], "a", 1) == 0) {
    if (argc < 6) {
      return -1;
    }
    if (CMHF_CopyString(g_issuer_file_path, argv[2], sizeof(g_issuer_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_my_cert_file_path, argv[3], sizeof(g_my_cert_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_recon_priv_file_path, argv[4], sizeof(g_recon_priv_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_init_priv_file_path, argv[5], sizeof(g_init_priv_file_path)) < 0) { return -1; }
    g_op = kCMHFOperation_MakeApp;
    if ((argc >= 7) && (strncmp(argv[6], "on", 2) == 0)) {
      g_dbg = true;
    }
  }
  // 익명 인증서 관련 cmhf 생성
  else if (strncmp(argv[1], "p", 1) == 0) {
    if (argc < 6) {
      return -1;
    }
    if (CMHF_CopyString(g_issuer_file_path, argv[2], sizeof(g_issuer_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_my_certs_dir, argv[3], sizeof(g_my_certs_dir)) < 0) { return -1; }
    if (CMHF_CopyString(g_seed_priv_file_path, argv[4], sizeof(g_seed_priv_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_exp_key_file_path, argv[5], sizeof(g_exp_key_file_path)) < 0) { return -1; }
    g_op = kCMHFOperation_MakePseudonym;
    if ((argc >= 7) && (strncmp(argv[6], "on", 2) == 0)) {
      g_dbg = true;
    }
  }
  // 식별 인증서 관련 cmhf 생성
  else if (strncmp(argv[1], "i", 1) == 0) {
    if (argc < 6) {
      return -1;
    }
    if (CMHF_CopyString(g_issuer_file_path, argv[2], sizeof(g_issuer_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_my_certs_dir, argv[3], sizeof(g_my_certs_dir)) < 0) { return -1; }
    if (CMHF_CopyString(g_seed_priv_file_path, argv[4], sizeof(g_seed_priv_file_path)) < 0) { return -1; }
    if (CMHF_CopyString(g_exp_key_file_path, argv[5], sizeof(g_exp_key_file_path)) < 0) { return -1; }
    g_op = kCMHFOperation_MakeId;
    if ((argc >= 7) && (strncmp(argv[6], "on", 2) == 0)) {
      g_dbg = true;
    }
  }
  else {
    return -1;
  }

  return 0;
}


/**
 * @brief 유틸리티 메인 함수
 * @param[in] argc 입력된 실행파라미터 개수
 * @param[in] argv 입력된 실행파라미터(들)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int main(int argc, const char *argv[])
{
  /*
   * 입력 파라미터를 파싱하여 저장한다.
   */
  int ret = CMHF_ParseInputParameters(argc, argv);
  if (ret < 0) {
    CMHF_Usage(argv[0]);
    return -1;
  }

  /*
   * dot2 라이브러리를 초기화한다.
   */
  Dot2LogLevel log_level;
  if (g_dbg == true) {
    log_level = kDot2LogLevel_Event;
  } else {
    log_level = kDot2LogLevel_Err;
  }
  ret = Dot2_Init(log_level, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default);
  if (ret < 0) {
    printf("Fail to Dot2_Init() - %d\n", ret);
    return -1;
  }

  /*
   * 각 동작을 수행한다.
   */
  switch (g_op) {
    case kCMHFOperation_MakeApp:
      CMHF_MakeApplicationCMHF();
      break;
    case kCMHFOperation_MakePseudonym:
      CMHF_MakePseudonymCMHF();
      break;
    case kCMHFOperation_MakeId:
      CMHF_MakeIdentificationCMHF();
      break;
    default:
      return -1;
  }

  return 0;
}


/**
 * @brief 바이트열 내용을 화면에 출력한다.
 * @param[in] desc 바이트열 설명문
 * @param[in] octets 출력할 바이트열
 * @param[in] len 바이트열의 길이
 */
void CMHF_PrintOctets(const char *desc, const uint8_t *octets, size_t len)
{
  printf("%s 0x", desc);
  for (size_t i = 0; i < len; i++) {
    printf("%02X", *(octets + i));
  }
  printf("\n");
}
