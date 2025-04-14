/** 
 * @file
 * @brief WSM 테스트 유틸리티 메인 헤더 파일
 * @date 2021-02-25
 * @author gyun
 */


#ifndef V2X_SW_WSM_TEST_LTEV2X_H
#define V2X_SW_WSM_TEST_LTEV2X_H


// 시스템 헤더 파일
#include <pthread.h>
#include <stdint.h>

// 의존 헤더 파일
#include "gpsd/gps.h"

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"
#include "ltev2x-hal/ltev2x-hal.h"
#include "wlanaccess/wlanaccess.h"
#include "v2x-sw.h"


/// V2X 통신 인터페이스 개수
#define V2X_IF_NUM (2)

/*
 * 입력 파라미터 기본값
 */
#define DEFAULT_DEV_NAME "/dev/spidev1.1"
#define DEFAULT_IF_IDX (0) ///< 기본 송신 인터페이스
#define DEFAULT_TX_FLOW_TYPE (1) ///< 기본 송신플로우 유형 (=SPS)
#define DEFAULT_PSID (32) ///< 기본 PSID
#define DEFAULT_POWER (20) ///< 기본 송신 파워 (dBm 단위)
#define DEFAULT_PRIORITY (7) ///< 기본 우선순위
#define DEFAULT_MCS_INDEX (0) ///< 기본 MCS index (kLalMCSindex_QPSK_0_13)
#define DEFAULT_WSM_BODY_LEN (100) ///< WSM body 길이 기본 길이
#define DEFAULT_TX_INTERVAL (100000) ///< 기본 전송 주기 (usec 단위)
#define DEFAULT_DBG (0) ///< 기본 디버그 메시지 출력 여부
#define DEFAULT_LIB_DBG (1) ///< 라이브러리 로그 메시지 출력 레벨
#define LATITUDE_UNAVAILABLE (900000001) ///< 유효하지 않은 위도 (per SAE J2735)
#define LONGITUDE_UNAVAILABLE (1800000001) ///< 유효하지 않은 경도 (per SAE J2735)
#define SPEED_UNAVAILABLE (UINT16_MAX) ///< 유효하지 않은 속도


/**
 * @brief 어플리케이션 동작 유형
 */
enum eOperationType
{
  kOperationType_Rx, ///< 수신동작 수행
  kOperationType_Tx, ///< 송신동작 수행
  kOperationType_Max = kOperationType_Tx
};
typedef unsigned int Operation; ///< @ref eOperationType


/**
 * @brief 어플리케이션 관리정보
 */
struct MIB
{
  // 장치 상태 정보 (현 상태를 읽어 온다)
  struct {
    struct gps_data_t gps_data; ///< GPS 정보
  } status;

  // 장치 동작 정보 (입력 파라미터에 의해 설정된다).
  struct {
    char dev_name[256]; ///< LTE-V2X 통신 디바이스 이름
    Operation op; ///< 어플리케이션 동작 유형
    LTEV2XHALTxFlowType tx_flow_type; ///< 송신 플로우 유형
    Dot3PSID psid; ///< 송신 또는 수신하고자 하는 PSID
    unsigned int tx_if_idx; ///< WSM 송신 인터페이스 식별번호
    Dot3Power tx_power; ///< WSM 송신에 사용되는 파워
    Dot3Priority tx_priority; ///< WSM 송신에 사용되는 우선순위
    Dot3WSMPayloadSize tx_wsm_body_len; ///< 송신 WSM body 의 길이
    unsigned int tx_interval; ///< 송신 주기 (usec 단위)
    bool dbg; ///< 디버그 메시지 출력 여부
    unsigned int lib_dbg; ///< V2X 라이브러리 로그메시지 레벨
  } op;

  uint32_t seq; ///< 테스트 메시지 순서번호(전송 시마다 1씩 증가)
};


/*
 * 테스트 메시지 헤더 형식
 */
struct TestMessageHeader
{
  uint32_t seq; ///< 메시지 순서번호. 전송 시마다 1씩 증가한다.
  int32_t lat; ///< 위도 (0.1 microdegree 단위)
  int32_t lon; ///< 경도 (0.1 microdegree 단위)
  uint16_t speed; ///< 속도 (meter/s 단위)
  uint16_t year; ///< 현재 년
  uint8_t month; ///< 현재 월
  uint8_t day; ///< 현재 일
  uint8_t hour; ///< 현재 시
  uint8_t minute; ///< 현재 분
  uint8_t second; ///< 현재 초
  uint16_t msecond; ///< 현재 밀리초
} __attribute__((packed));


/*
 * 프로그램에서 사용되는 전역 변수 및 함수
 */
extern struct MIB g_mib;
int WSM_TEST_LTEV2X_ParsingInputParameters(int argc, char *argv[]);
void WSM_TEST_LTEV2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_param);
int WSM_TEST_LTEV2X_InitTxOperation(unsigned int interval);
void WSM_TEST_LTEV2X_ReleaseTxOperation(void);


#endif //V2X_SW_WSM_TEST_LTEV2X_H
