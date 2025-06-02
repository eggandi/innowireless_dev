/**
 * @file
 * @brief LTE-V2X 기능 구현
 * @date 2022-09-17
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"
#include "dot3-2016/dot3.h"
#include "ltev2x-hal/ltev2x-hal.h"

// 어플리케이션 헤더 파일
#include "bsmd.h"


/**
 * @brief 어플리케이션 종료 시에 호출되는 시그널 함수
 * @param[in] signum 시그널 번호
 *
 * 종료 시에 반드시 LAL_Close()가 호출되어야 한다. (소켓 재사용을 위해)
 */
static void BSMD_LTE_V2X_Terminate(int signum)
{
  (void)signum;
  LTEV2XHAL_Close();
  exit(0);
}


/**
 * @brief 프로그램 종료 시 호출될 종료 시그널 핸들러를 등록한다.
 *
 * LTE-V2X 사용 시, 종료 시에 반드시 LAL_Close()가 호출되어야 한다.
 */
void BSMD_LTE_V2X_InitTerminateHandler(void)
{
  Log(kBSMDLogLevel_Event, "Initialize LTE-V2X terminate handler\n");

  struct sigaction sig_action;
  sig_action.sa_handler = BSMD_LTE_V2X_Terminate;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = 0;
  sigaction(SIGINT, &sig_action, NULL);
  sigaction(SIGHUP, &sig_action, NULL);
  sigaction(SIGTERM, &sig_action, NULL);
  sigaction(SIGSEGV, &sig_action, NULL);
}


/**
 * @brief LTE-V2X 송신 플로우를 등록한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int BSMD_LTE_V2X_RegisterTransmitFlow(void)
{
  Log(kBSMDLogLevel_Event, "Preapare LTE-V2X transmit\n");

  struct LTEV2XHALTxFlowParams params;
  memset(&params, 0x00, sizeof(struct LTEV2XHALTxFlowParams));
  params.index = kLTEV2XHALTxFLowIndex_SPS1;
  params.interval = BSM_TX_INTERVAL;
  params.priority = BSM_DEFAULT_PRIORITY;
  params.size = kLTEV2XHALMSDUSize_Max;

  int ret = LTEV2XHAL_RegisterTransmitFlow(params);
  if (ret < 0) {
    Err("Fail to prepare LTE-V2X transmit - LTEV2XHAL_RegisterTransmitFlow() failed: %d\n", ret);
    return -1;
  }

  Log(kBSMDLogLevel_Event, "Success to prepare LTE-V2X transmit\n");
  return 0;
}


/**
 * @brief LTE-V2X WSM을 생성하여 전송한다.
 * @param[in] wsdu WSM에 수납될 WSDU
 * @param[in] wsdu_size WSM에 수납될 WSDU의 길이
 * @param[in] priority 전송 우선순위
 */
void BSMD_LTE_V2X_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, LTEV2XHALPriority priority)
{
  /*
   * WSM을 생성한다.
   */
  int ret;
  struct Dot3WSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.chan_num = kDot3ChannelNumber_NA;
  wsm_params.datarate = kDot3DataRate_NA;
  wsm_params.transmit_power = kDot3Power_NA;
  wsm_params.psid = BSM_PSID;
  Log(kBSMDLogLevel_Event, "Construct LTE-V2X WSM\n");
  size_t wsm_size;
  uint8_t *wsm = Dot3_ConstructWSM(&wsm_params, wsdu, wsdu_size, &wsm_size, &ret);
  if (wsm == NULL) {
    Err("Fail to construct LTE-V2X WSM - Dot3_ConstructWSM() failed - %d\n", ret);
    return;
  }
  Log(kBSMDLogLevel_Event, "Success to construct %d-bytes LTE-V2X WSM\n", wsm_size);
  BSMD_PrintPacketDump(kBSMDLogLevel_PktDump, wsm, wsm_size);

  /*
   * WSM을 전송한다.
   */
  struct LTEV2XHALMSDUTxParams tx_params;
  memset(&tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
  tx_params.tx_flow_type = kLTEV2XHALTxFlowType_SPS;
  tx_params.tx_flow_index = kLTEV2XHALTxFLowIndex_SPS1;
  tx_params.priority = priority;
  tx_params.tx_power = BSM_TX_POWER;
  tx_params.dst_l2_id = kLTEV2XHALL2ID_Broadcast;

  ret = LTEV2XHAL_TransmitMSDU(wsm, wsm_size, tx_params);
  if (ret < 0) {
    Err("Fail to transmit LTE-V2X WSM - LTEV2XHAL_TransmitMSDU() failed: %d\n", ret);
  }
  Log(kBSMDLogLevel_Event, "Success to transmit LTE-V2X WSM\n");

  free(wsm);
}


/**
 * @brief LTE-V2X MSDU 수신콜백함수
 * @param[in] msdu 수신된 MSDU 데이터
 * @param[in] msdu_size 수신된 MSDU 데이터 길이
 */
void BSMD_LTE_V2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_param)
{
  Log(kBSMDLogLevel_Event, "Proces %u-bytes rx LTE-V2X MSDU\n", msdu_size);

  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateCV2XPacketParseData(msdu, msdu_size);
  if (parsed == NULL) {
    Err("Fail to process rx LTE-V2X MSDU - V2X_AllocateCV2XPacketParseData() failed\n");
    return;
  }

  /*
   * WSM을 파싱한다.
   */
  int ret;
  parsed->wsdu = Dot3_ParseWSM(parsed->pkt,
                               parsed->pkt_size,
                               &(parsed->mac_wsm.wsm),
                               &(parsed->wsdu_size),
                               &(parsed->interested_psid),
                               &ret);
  if (parsed->wsdu == NULL) {
    Err("Fail to process rx LTE-V2X MSDU - Dot3_ParseWSMMPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }

  /*
   * SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  struct Dot2SPDUProcessParams params;
  memset(&params, 0, sizeof(params));
  params.rx_psid = parsed->mac_wsm.wsm.psid;
  params.rx_pos.lat = kDot2Latitude_Unavailable;
  params.rx_pos.lon = kDot2Longitude_Unavailable;
  ret = Dot2_ProcessSPDU(parsed->wsdu, parsed->wsdu_size, &params, parsed);
  if (ret < 0) {
    Err("Fail to process received LTE-V2X MSDU - Dot2_ProcessSPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
}
