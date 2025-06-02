/** 
  * @file 
  * @brief 부트스트래핑 유틸리티 입력 파라미터 처리 기능 구현
  * @date 2022-07-17 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// 유틸리티 헤더 파일
#include "bootstrap.h"


/**
 * @brief 특정 시간을 Time32 값으로 변환한다.
 * @param[in] year 년
 * @param[in] mon 월
 * @param[in] day 일
 * @param[in] hour 시
 * @param[in] min 분
 * @param[in] sec 초
 * @return Time32 값
 */
static Dot2Time32 BOOTSTRAP_ConvertToTime32(int year, int mon, int day, int hour, int min, int sec)
{
  struct tm tm_;
  memset(&tm_, 0, sizeof(tm_));
  tm_.tm_year = year - 1900;
  tm_.tm_mon = mon - 1;
  tm_.tm_mday = day;
  tm_.tm_hour = hour;
  tm_.tm_min = min;
  tm_.tm_sec = sec;
  time_t t = mktime(&tm_);
  if (t < 0) {
    t = 0;
  }
  Dot2Time32 time = Dot2_ConvertSystemTimeToTime32(t);
  return time;
}


/**
 * @brief 입력 파라미터 중 "start" 옵션을 처리한다.
 */
static void BOOTSTRAP_ProcessParsedOption_START(void)
{
  char t[10];
  memset(t, 0, sizeof(t));
  memcpy(t, optarg, 4);
  int year = (int)strtoul(t, 0, 10);
  memset(t, 0, sizeof(t));
  memcpy(t, optarg + 4, 2);
  int mon = (int)strtoul(t, 0, 10);
  memset(t, 0, sizeof(t));
  memcpy(t, optarg + 6, 2);
  int day = (int)strtoul(t, 0, 10);
  memset(t, 0, sizeof(t));
  memcpy(t, optarg + 8, 2);
  int hour = (int)strtoul(t, 0, 10);
  memset(t, 0, sizeof(t));
  memcpy(t, optarg + 10, 2);
  int min = (int)strtoul(t, 0, 10);
  memset(t, 0, sizeof(t));
  memcpy(t, optarg + 12, 2);
  int sec = (int)strtoul(t, 0, 10);
  Dot2Time32 time = BOOTSTRAP_ConvertToTime32(year, mon, day, hour, min, sec);
  g_cfg.gen.valid_start = time;
}


/**
 * @brief 입력 파라미터 중 "dur" 옵션을 처리한다.
 * @param[in] input_str dur 옵션 입력 문자열
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int BOOTSTRAP_ProcessParsedOption_DUR(char *input_str)
{
  char t[MAXLINE + 1];
  memset(t, 0, sizeof(t));
  size_t len = (strlen(input_str) > MAXLINE) ? MAXLINE : strlen(input_str);

  // 기간 값 처리 (마지막 글자 제외)
  memcpy(t, input_str, len - 1);
  g_cfg.gen.dur = (uint16_t)strtoul(t, 0 ,10);

  // 유형 값 처리 (마지막 글자)
  switch (*(input_str + len - 1)) {
    case 's':
      g_cfg.gen.dur_type = kDot2CertDurationType_Seconds;
      break;
    case 'm':
      g_cfg.gen.dur_type = kDot2CertDurationType_Minutes;
      break;
    case 'h':
      g_cfg.gen.dur_type = kDot2CertDurationType_Hours;
      break;
    case 'x':
      g_cfg.gen.dur_type = kDot2CertDurationType_SixtyHours;
      break;
    case 'y':
      g_cfg.gen.dur_type = kDot2CertDurationType_Years;
      break;
    default:
      return -1;
  }
  return 0;
}


/**
 * @brief 입력 파라미터 중 "region" 옵션을 처리한다.
 * @param[in] input_str region 옵션 입력 문자열
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int BOOTSTRAP_ProcessParsedOption_REGION(char *input_str)
{
  const char *delimiter =",";
  char *str = strdup(input_str);
  if (!str) {
    return -1;
  }
  char *token = strtok(str, delimiter);
  int cnt = 0;
  while (token) {
    g_cfg.gen.region[cnt] = (Dot2CountryCode)strtoul(token, 0, 10);
    cnt++;
    if (cnt >= kDot2IdentifiedRegionNum_Max) {
      break;
    }
    token = strtok(NULL, delimiter);
  }

  // region 값이 하나도 없으면 실패
  if (cnt == 0) {
    return -1;
  }
  g_cfg.gen.region_num = cnt;
  return 0;
}


/**
 * @brief 입력 파라미터 중 "psid" 옵션을 처리한다.
 * @param[in] input_str psid 옵션 입력 문자열
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int BOOTSTRAP_ProcessParsedOption_PSID(const char *input_str)
{
  const char *delimiter =",";
  char *str = strdup(input_str);
  if (!str) {
    return -1;
  }
  char *token = strtok(str, delimiter);
  int cnt = 0;
  while (token) {
    g_cfg.gen.psid[cnt] = (Dot2PSID)strtoul(token, 0, 10);
    cnt++;
    if (cnt >= kDot2CertPermissionNum_Max) {
      break;
    }
    token = strtok(NULL, delimiter);
  }

  // psid 값이 하나도 없으면 실패
  if (cnt == 0) {
    return -1;
  }
  g_cfg.gen.psid_num = cnt;
  return 0;
}


/**
 * @brief 입력 파라미터들에 대한 기본값을 설정한다.
 * @param[in] op 동작 유형
 */
static void BOOTSTRAP_SetDefaultInputParameters(BootstrapOperationType op)
{
  g_cfg.lib_dbg = DEFAULT_LIB_DBG;
  snprintf(g_cfg.init_priv_key_file, MAXLINE, "%s", g_default_init_priv_key_file);

  if (op == kBootstrapOperationType_Gen) {
    g_cfg.gen.valid_start = 0;
    BOOTSTRAP_ProcessParsedOption_DUR((char *)g_default_cert_valid_duration);
    BOOTSTRAP_ProcessParsedOption_REGION((char *)g_default_region);
    BOOTSTRAP_ProcessParsedOption_PSID((char *)g_default_cert_psid);
    snprintf(g_cfg.gen.ecreq_file, MAXLINE, "%s", g_default_ecreq_file);
  } else {
    snprintf(g_cfg.proc.enroll_cert_file, MAXLINE, "%s", g_default_enroll_cert_file);
    snprintf(g_cfg.proc.recon_priv_file, MAXLINE, "%s", g_default_enroll_recon_priv_file);
    snprintf(g_cfg.proc.rca_cert_file, MAXLINE, "%s", g_default_rca_cert_file);
    snprintf(g_cfg.proc.eca_cert_file, MAXLINE, "%s", g_default_eca_cert_file);
    snprintf(g_cfg.proc.ra_cert_file, MAXLINE, "%s", g_default_ra_cert_file);
    snprintf(g_cfg.proc.lccf_file, MAXLINE, "%s", g_default_lccf_file);
    snprintf(g_cfg.proc.ica_cert_file, MAXLINE, "%s", g_default_ica_cert_file);
    snprintf(g_cfg.proc.pca_cert_file, MAXLINE, "%s", g_default_pca_cert_file);
    snprintf(g_cfg.proc.crlg_cert_file, MAXLINE, "%s", g_default_crlg_cert_file);
    snprintf(g_cfg.proc.enroll_priv_key_file, MAXLINE, "%s", g_default_enroll_priv_key_file);
  }
}


/**
 * @brief 옵션값에 따라 각 옵션을 처리한다.
 * @param[in] option 옵션값 (struct option 의 4번째 멤버변수)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int BOOTSTRAP_ProcessParsedOption(int option)
{
  int ret = 0;
  switch (option) {
    case 0: {
      BOOTSTRAP_ProcessParsedOption_START(); // "start""
      break;
    }
    case 1: {
      ret = BOOTSTRAP_ProcessParsedOption_DUR(optarg); // "dur"
      break;
    }
    case 2: {
      ret = BOOTSTRAP_ProcessParsedOption_REGION(optarg); // "region"
      break;
    }
    case 3: {
      ret = BOOTSTRAP_ProcessParsedOption_PSID(optarg); // "psid"
      break;
    }
    case 4: {
      strcpy(g_cfg.gen.ecreq_file, optarg); // "req"
      break;
    }
    case 5: {
      strcpy(g_cfg.init_priv_key_file, optarg); // "ik"
      break;
    }
    case 6: {
      g_cfg.proc.ecresp_file_present = true;
      strcpy(g_cfg.proc.ecresp_file, optarg); // "resp"
      break;
    }
    case 7: {
      strcpy(g_cfg.proc.enroll_cert_file, optarg); // "ec"
      break;
    }
    case 8: {
      strcpy(g_cfg.proc.recon_priv_file, optarg); // "s"
      break;
    }
    case 9: {
      strcpy(g_cfg.proc.rca_cert_file, optarg); // "rca"
      break;
    }
    case 10: {
      strcpy(g_cfg.proc.eca_cert_file, optarg); // "eca"
      break;
    }
    case 11: {
      strcpy(g_cfg.proc.ra_cert_file, optarg); // "ra"
      break;
    }
    case 12: {
      strcpy(g_cfg.proc.lccf_file, optarg); // "lccf"
      break;
    }
    case 13: {
      strcpy(g_cfg.proc.ica_cert_file, optarg); // "ica"
      break;
    }
    case 14: {
      strcpy(g_cfg.proc.pca_cert_file, optarg); // "pca"
      break;
    }
    case 15: {
      strcpy(g_cfg.proc.crlg_cert_file, optarg); // "crlg"
      break;
    }
    case 16: {
      strcpy(g_cfg.proc.enroll_priv_key_file, optarg); // "ek"
      break;
    }
    case 17: {
      g_cfg.lib_dbg = (unsigned int)strtoul(optarg, 0, 10); // "libdbg"
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
int BOOTSTRAP_ParsingInputParameters(int argc, char *argv[])
{
  int c, option_idx = 0;
  struct option options[] = {
  {"start",  required_argument, 0, 0/*=getopt_long() 호출 시 option_idx 에 반환되는 값*/},
  {"dur",    required_argument, 0, 1},
  {"region", required_argument, 0, 2},
  {"psid",   required_argument, 0, 3},
  {"req",    required_argument, 0, 4},
  {"ik",    required_argument, 0, 5},
  {"resp",    required_argument, 0, 6},
  {"ec",     required_argument, 0, 7},
  {"s",      required_argument, 0, 8},
  {"rca",    required_argument, 0, 9},
  {"eca",    required_argument, 0, 10},
  {"ra",     required_argument, 0, 11},
  {"lccf",   required_argument, 0, 12},
  {"ica",   required_argument, 0, 13},
  {"pca",   required_argument, 0, 14},
  {"crlg",   required_argument, 0, 15},
  {"ek",   required_argument, 0, 16},
  {"libdbg", required_argument, 0, 17},
  {0, 0,                        0, 0} // 옵션 배열은 {0,0,0,0} 센티넬에 의해 만료된다.
  };

  /*
   * 동작 유형을 설정하고 기본설정정보를 설정한다.
   */
  if (!memcmp(argv[1], "gen", 3)) {
    g_cfg.op = kBootstrapOperationType_Gen;
  } else if (!memcmp(argv[1], "proc", 4)) {
    g_cfg.op = kBootstrapOperationType_Proc;
  } else {
    printf("Invalid operation - %s\n", argv[1]);
    return -1;
  }
  BOOTSTRAP_SetDefaultInputParameters(g_cfg.op);

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
    int ret = BOOTSTRAP_ProcessParsedOption(c);
    if (ret < 0) {
      return ret;
    }
  }

  /*
   * 설정정보를 화면에 출력한다.
   */
  BOOTSTRAP_PrintBootstrapCFG();

  return 0;
}

