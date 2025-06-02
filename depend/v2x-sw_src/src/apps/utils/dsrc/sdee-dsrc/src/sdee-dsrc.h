/** 
 * @file
 * @brief sdee-dsrc 샘플 어플리케이션 메인 헤더 파일
 * @date 2020-05-26
 * @author gyun
 */


#ifndef V2X_SW_SDEE_DSRC_H
#define V2X_SW_SDEE_DSRC_H


// 시스템 헤더 파일
#include <pthread.h>
#include <stdint.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "wlanaccess/wlanaccess.h"


// 문자열 버퍼 최대길이
#define MAXLINE 255


/*
 * 입력 파라미터 기본값
 */
#define DEFAULT_PSID 32
#define DEFAULT_PAYLOAD_SIZE 0 // 0일 경우 사전에 정의된 BSM 메시지가 전송됨.
#define DEFAULT_CHAN 178
#define DEFAULT_TX_INTERVAL 100000
#define DEFAULT_LAT 374856150
#define DEFAULT_LON 1270392830
#define DEFAULT_IF_IDX 0
#define DEFAULT_TIMESLOT 0
#define DEFAULT_DATARATE 12
#define DEFAULT_POWER 10
#define DEFAULT_PRIORITY 7
#define DEFAULT_DBG 1
#define DEFAULT_LIB_DBG 1
#define DEFAULT_CMHF_DIR "certificates/cmhf/pseudonym"
#define DEFAULT_RCA_CERT_FILE "certificates/scc/rca"
#define DEFAULT_ICA_CERT_FILE "certificates/scc/ica"
#define DEFAULT_PCA_CERT_FILE "certificates/scc/pca"



/**
 * @brief 어플리케이션 동작 유형
 */
enum eOperationType
{
  kOperationType_RxOnly, ///< 수신동작만 수행
  kOperationType_Trx, ///< 송수신동작 수행
  kOperationType_Loopback, ///< 루프백 테스트
  kOperationType_Max = kOperationType_Loopback
};
typedef unsigned int Operation; ///< @ref eOperationType


/**
 * @brief 송신 메시지 유형
 */
enum eMsgType
{
  kMsgType_Unsecured, ///< 비보안 메시지 유형
  kMsgType_Signed ///< 서명 메시지 유형
};
typedef unsigned int MsgType; ///< @ref eMsgType


/**
 * @brief 로그메시지 출력 레벨
 */
enum eDbgMsgLevel
{
  kDbgMsgLevel_Nothing, ///< 미출력
  kDbgMsgLevel_Event, ///< 이벤트 출력
  kDbgMsgLevel_MsgDump, ///< 메시지 hexdump 출력
  kDbgMsgLevel_Max = kDbgMsgLevel_MsgDump
};
typedef unsigned int DbgMsgLevel; ///< @ref eDbgMsgLevel


/**
 * @brief 어플리케이션 관리정보
 */
struct MIB
{
  Operation op; ///< 어플리케이션 동작 유형
  MsgType msg_type; ///< 송신 메시지 유형
  Dot2PSID psid; ///< 송신 또는 수신하고자 하는 PSID
  Dot2MsgSize payload_size; ///< 페이로드 크기
  unsigned int tx_interval; ///< 송신주기(usec단위)
  DbgMsgLevel dbg; ///< 디버그 메시지 출력 레벨
  unsigned int lib_dbg; ///< V2X 라이브러리 디버그 메시지 출력 레벨
  Dot2Latitude lat; ///< 위도
  Dot2Longitude lon; ///< 경도
  char cmhf_dir[MAXLINE]; ///< 인증서(CMHF) 디렉토리
  char rca_cert_file_path[MAXLINE]; ///< RCA 인증서 파일경로
  char ica_cert_file_path[MAXLINE]; ///< ICA 인증서 파일경로
  char pca_cert_file_path[MAXLINE]; ///< PCA 인증서 파일경로
  WalChannelNumber chan[2]; ///< 시간슬롯별 채널번호
  uint8_t mac_addr[MAC_ALEN]; ///< 나의 MAC 주소
};


/*
 * 프로그램에서 사용되는 전역 변수 및 함수
 */
extern struct MIB g_mib;
void SDEE_DSRC_Print(const char *func, const char *format, ...);
int SDEE_DSRC_ParsingInputParameters(int argc, char *argv[]);
int SDEE_DSRC_InitTxOperation(unsigned int interval);
void SDEE_DSRC_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *rx_params);
int SDEE_DSRC_RegisterCryptoMaterials(void);
void SDEE_DSRC_ProcessSPDUCallback(Dot2ResultCode result, void *priv);


#endif //V2X_SW_SDEE_DSRC_H
