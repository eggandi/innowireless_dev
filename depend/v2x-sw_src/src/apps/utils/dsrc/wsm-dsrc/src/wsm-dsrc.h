/**
 * @file
 * @brief wsm-dsrc 어플리케이션 메인 헤더파일
 * @date 2019-08-10
 * @author gyun
 */

#ifndef V2X_WSM_DSRC_H
#define V2X_WSM_DSRC_H


// 시스템 헤더 파일
#include <pthread.h>
#include <stdint.h>

// 라이브러리 헤더 파일
#include "dot3-2016/dot3.h"
#include "wlanaccess/wlanaccess.h"
#include "v2x-sw.h"


/// V2X 통신 인터페이스 개수
#define V2X_IF_NUM (2)

/*
 * 입력 파라미터 기본값
 */
#define DEFAULT_IF_IDX 0
#define DEFAULT_PSID 32
#define DEFAULT_CHAN_NUM 178
#define DEFAULT_DATARATE 12
#define DEFAULT_POWER 10
#define DEFAULT_PRIORITY 7
#define DEFAULT_WSM_BODY_LEN 100
#define DEFAULT_TX_INTERVAL 100000
#define DEFAULT_DBG 1
#define DEFAULT_LIB_DBG 1


/**
 * @brief 어플리케이션 동작 유형
 */
enum eOperationType
{
  kOperationType_rx_only, ///< 수신동작만 수행
  kOperationType_trx, ///< 송수신동작 수행
  kOperationType_max = kOperationType_trx
};
typedef unsigned int Operation; ///< @ref eOperationType


/**
 * @brief 로그메시지 출력 레벨
 */
enum eDbgMsgLevel
{
  kDbgMsgLevel_nothing, ///< 미출력
  kDbgMsgLevel_event, ///< 이벤트 출력
  kDbgMsgLevel_msgdump, ///< 메시지 hexdump 출력
  kDbgMsgLevel_max = kDbgMsgLevel_msgdump
};
typedef unsigned int DbgMsgLevel; ///< @ref eDbgMsgLevel


/**
 * @brief 어플리케이션 관리정보
 */
struct MIB
{
  Operation op; ///< 어플리케이션 동작 유형
  unsigned int if_num; ///< v2x 송수신 인터페이스 총 개수 (플랫폼 하드웨어에 의존적이다)
  Dot3PSID psid; ///< 송신 또는 수신하고자 하는 PSID
  DbgMsgLevel dbg; ///< 디버그 메시지 출력 레벨
  unsigned int lib_dbg; ///< V2X 라이브러리 디버그 메시지 출력 레벨
  uint8_t my_addr[V2X_IF_NUM][MAC_ALEN]; ///< 인터페이스 MAC 주소
  unsigned int tx_if_idx; ///< WSM 송신 인터페이스 식별번호
  Dot3ChannelNumber tx_chan_num; ///< WSM 송신 채널번호
  Dot3DataRate tx_datarate; ///< WSM 송신에 사용되는 데이터레이트
  Dot3Power tx_power; ///< WSM 송신에 사용되는 파워
  Dot3Priority tx_priority; ///< WSM 송신에 사용되는 우선순위
  uint8_t tx_dst_mac_addr[MAC_ALEN]; ///< WSM 송신에 사용되는 목적지 MAC 주소
  Dot3WSMPayloadSize tx_wsm_body_len; ///< 송신 WSM body 의 길이
  unsigned int tx_interval; ///< 송신 주기 (usec 단위)
};


/*
 * 프로그램에서 사용되는 전역 변수 및 함수
 */
extern struct MIB g_mib;
void WSM_DSRC_Print(const char *func, const char *format, ...);
int WSM_DSRC_ParsingInputParameters(int argc, char *argv[]);
void WSM_DSRC_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *rx_params);
int WSM_DSRC_InitTxOperation(unsigned int interval);
void WSM_DSRC_ReleaseTxOperation(void);


#endif //V2X_WSM_DSRC_H
