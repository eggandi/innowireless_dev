/** 
 * @file
 * @brief sec-tester 유틸리티 구현 메인 파일
 * @date 2020-08-27
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#if defined(_CONDOR5_) || defined(_CONDOR6_)
#include "wlanaccess/wlanaccess.h"
#endif

// 유틸리티 헤더 파일
#include "sec-tester.h"


Operation g_op; ///< 테스트할 동작
Mode g_mode; ///< 테스트 모드
bool g_relevance_consistency_check; ///< relevance/concistency check 수행 여부 (msg_process 테스트 시에만 사용)
Dot2LogLevel g_dbg = kDot2LogLevel_Err; ///< libdot2 로그메시지 출력레벨


/**
 * @brief 유틸리티 사용법을 화면에 출력한다.
 * @param[in] app_filename 어플리케이션 실행파일명
 */
void SEC_TESTER_Usage(const char *app_filename)
{
  printf("\n\n Description: Utility to test security function using v2x-sw libraries\n");
  printf(" Version: %s\n", _VERSION_);
  printf(" Author: gyun\n");
  printf(" Email: junghg@keti.re.kr\n");
  printf("\n Usage: %s <operation> <mode> on|off [dbg]\n\n", app_filename);
  printf("          operaiton: msg_gen, msg_process\n");
  printf("          mode: single, burst, check\n");
  printf("          on|off: relevance/consistency check on/off in case of msg_process test\n");
  printf("          dbg: libdot2 debug message print level. If not specified, set to %u\n", kDot2LogLevel_Err);
  printf("                             0: nothing, 1: err, 2: init, 3: event, 4: message hexdump\n\n");
  printf(" msg_gen: Check 1609.2 message generation performace\n");
  printf(" msg_process: Check 1609.2 message process performace\n");
  printf(" single: Calculate latency to generate/process single message\n");
  printf(" burst: Calculate average latency and process count for 1 second to generate/process %u messages\n", BURST_MODE_TEST_CNT);
  printf(" check: Only for \"msg_process\" opration. Check if 1609.2 message process function works good\n");
  printf("\n");
}


/**
 * @brief 입력파라미터를 파싱한다.
 * @param[in] argc 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 개수 (유틸리티 실행파일명 포함)
 * @param[in] argv 유틸리티 실행 시 입력되는 명령줄 내 파라미터들의 문자열 집합 (유틸리티 실행파일명 포함)
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int SEC_TESTER_ParseInputParams(int argc, char *argv[])
{
  /*
   * 파라미터가 부족하면 사용법을 출력하고 종료한다.
   */
  if (argc < 4) {
    SEC_TESTER_Usage(argv[0]);
    return -1;
  }

  /*
   * operation 파라미터 처리
   */
  if (strcmp(argv[1], "msg_gen") == 0){
    g_op = kOperation_MsgGenerate;
  } else if (strcmp(argv[1], "msg_process") == 0){
    g_op = kOperation_MsgProcess;
  } else {
    SEC_TESTER_Usage(argv[0]);
    return -1;
  }

  /*
   * mode 파라미터 처리
   */
  if (strcmp(argv[2], "single") == 0) {
    g_mode = kMode_Single;
  } else if (strcmp(argv[2], "burst") == 0) {
    g_mode = kMode_Burst;
  } else {
    g_mode = kMode_Check;
  }

  /*
   * on|off 파라미터 처리
   */
  if (strcmp(argv[3], "on") == 0) {
    g_relevance_consistency_check = true;
  } else {
    g_relevance_consistency_check = false;
  }

  /*
   * dbg 파라미터 처리
   */
  if (argc >= 5) {
    g_dbg = (Dot2LogLevel)strtoul(argv[4], NULL, 10);
  }

  return 0;
}


/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int SEC_TESTER_InitV2XLibs(void)
{
  printf("Initialize V2X libraries\n");

  int ret;

#if defined(_CONDOR5_) || defined(_CONDOR6_) // Condor5/6처럼 H/W 기반 서명 기능을 사용하는 경우 필요하다.
  /*
   * 접속계층 라이브러리를 초기화한다.
   */
  ret = WAL_Init(kWalLogLevel_Err);
  if (ret < 0) {
    printf("Fail to initialize wlanaccess library - WAL_Open() failed: %d\n", ret);
    return -1;
  }
#endif

  /*
   * dot2 라이브러리를 초기화하고 메시지처리 콜백함수를 등록한다.
   */
  ret = Dot2_Init(g_dbg, kDot2SigningParamsPrecomputeInterval_Default, "/dev/urandom", kDot2LeapSeconds_Default);
  if (ret < 0) {
    printf("Fail to initialize dot2 library - Dot2_Init() failed: %d\n", ret);
    return -1;
  }
  Dot2_RegisterProcessSPDUCallback(SEC_TESTER_ProcessSPDUCallback);

  /*
   * dot3 라이브러리를 초기화한다.
   */
  ret = Dot3_Init(kDot3LogLevel_Err);
  if (ret < 0) {
    printf("Fail to initialize dot3 library - Dot3_Init() failed: %d\n", ret);
    return -1;
  }

  /*
   * 인증서 등 보안관련 정보를 등록한다.
   */
  return SEC_TESTER_RegisterCryptoMaterials();
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
   * 입력 파라미터들을 파싱하여 저장한다.
   */
  int ret = SEC_TESTER_ParseInputParams(argc, argv);
  if (ret < 0) {
    return -1;
  }

  printf("Running sec-tester utility..\n");

  /*
   * V2X 라이브러리를 초기화한다.
   */
  ret = SEC_TESTER_InitV2XLibs();
  if (ret < 0) {
    return -1;
  }

  /*
   * 테스트를 수행한다.
   */
  if (g_op == kOperation_MsgGenerate) {
    SEC_TESTER_MsgGenerateTest();
  } else if (g_op == kOperation_MsgProcess) {
    if ((g_mode == kMode_Single) || (g_mode == kMode_Burst)) {
      SEC_TESTER_MsgProcessTest();
    } else {
      SEC_TESTER_SampleMsgProcessTest();
    }
  }

  while(1) {
    sleep(1);
  }

  return 0;
}
