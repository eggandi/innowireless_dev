/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>

// 라이브러리 헤더 파일
#if defined(_LTEV2X_HAL_)
#include "ltev2x-hal/ltev2x-hal.h"
#else
#include "lteaccess/lteaccess.h"
#endif

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 어플리케이션 종료 시에 호출되는 시그널 함수
 * @param[in] signum 시그널 번호
 *
 * 종료 시에 반드시 LAL_Close()가 호출되어야 한다. (소켓 재사용을 위해)
 */
static void TCIA2023_LTE_V2X_Terminate(int signum)
{
  (void)signum;
#if defined(_LTEV2X_HAL_)
  LTEV2XHAL_Close();
#else
  LAL_Close();
#endif
  exit(0);
}


/**
 * @brief 프로그램 종료 시 호출될 종료 시그널 핸들러를 등록한다.
 *
 * LTE-V2X 사용 시, 종료 시에 반드시 LAL_Close()가 호출되어야 한다.
 */
void TCIA2023_LTE_V2X_InitTerminateHandler(void)
{
  Log(kTCIA3LogLevel_Init, "Initialize LTE-V2X terminate handler\n");

  struct sigaction sig_action;
  sig_action.sa_handler = TCIA2023_LTE_V2X_Terminate;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = 0;
  sigaction(SIGINT, &sig_action, NULL);
  sigaction(SIGHUP, &sig_action, NULL);
  sigaction(SIGTERM, &sig_action, NULL);
  sigaction(SIGSEGV, &sig_action, NULL);
}

#if defined(_LTEV2X_HAL_)
/**
 * @brief LTE-V2X 송신 플로우를 등록한다.
 * @param[in] index 송신 플로우 인덱스
 * @param[in] priority 송신 우선순위
 * @param[in] tx_interval 송신 주기(msec 단위)
 * @param[in] size 송신 패킷 크기
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_LTE_V2X_RegisterTransmitFlow(LTEV2XHALTxFlowIndex index, LTEV2XHALPriority priority, LTEV2XHALTxFlowInterval tx_interval, LTEV2XHALMSDUSize size)
{
  Log(kTCIA3LogLevel_Event, "Preapare LTE-V2X transmit - index: %u, priority: %u, tx_interval: %umsec, size: %u\n",
      index, priority, tx_interval, size);
  int ret;

  struct LTEV2XHALTxFlowParams params = {0};
  params.index = index;
  params.interval = (tx_interval == 0 ? kLTEV2XHALTxFLowInterval_Default : tx_interval);
  params.priority = priority;
  params.size = (size == 0 ? kLTEV2XHALMSDUSize_Max : size + 20);
  ret = LTEV2XHAL_RegisterTransmitFlow(params);
  if (ret < 0) {
    Err("Fail to prepare LTE-V2X transmit - LTEV2XHAL_RegisterTransmitFlow() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to prepare LTE-V2X transmit\n");
  return 0;
}
#else
/**
 * @brief LTE-V2X 송신 플로우를 등록한다.
 * @param[in] psid PSID
 * @param[in] power 송신 파워
 * @param[in] priority 송신 우선순위
 * @param[in] tx_interval 송신 주기(msec 단위)
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_LTE_V2X_RegisterTransmitFlow(Dot3PSID psid, LalPower power, LalPriority  priority, unsigned int tx_interval)
{
  Log(kTCIA3LogLevel_Event, "Preapare LTE-V2X transmit - psid: %u, power: %d, priority: %u, tx_interval: %umsec\n",
      psid, power, priority, tx_interval);

  struct LalTxFlowParams params = {0};
  params.psid = psid;
  params.type = kLalTxFlowType_Event;
  params.power = power;
  params.priority = priority;
  params.interval = tx_interval;
  params.max_payload_size = kLalMSDUSize_Max;
  int ret = LAL_RegisterTransmitFlow(&params);
  if ((ret < 0) && (ret != -kLalResult_Duplicated)) { // TS의 제어에 따라 등록을 반복하므로 중복정보실패는 무시한다.
    Err("Fail to prepare LTE-V2X transmit - LAL_RegisterTransmitFlow() failed: %d\n", ret);
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to prepare LTE-V2X transmit\n");
  return 0;
}
#endif

/**
 * @brief LTE-V2X WSM을 생성하여 전송한다.
 * @param[in] wsdu WSM에 수납될 WSDU
 * @param[in] wsdu_size WSM에 수납될 WSDU의 길이
 * @param[in] timeslot 전송 TimeSlot
 */
void TCIA2023_LTE_V2X_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, Dot3TimeSlot timeslot)
{
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);

  int ret;
  size_t wsm_size = 0;
  uint8_t *wsm = NULL;

  /*
   * WSM을 생성한다.
   */
  struct Dot3WSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.chan_num = (wsm_tx_info->chan_num_ext == true) ? 183 : kDot3ChannelNumber_NA;
  wsm_params.datarate = (wsm_tx_info->datarate_ext == true) ? 12 : kDot3DataRate_NA;
  wsm_params.transmit_power = (wsm_tx_info->txpower_ext == true) ? 20 : kDot3Power_NA;
  wsm_params.psid = wsm_tx_info->psid;
  Log(kTCIA3LogLevel_DetailedEvent, "Construct C-V2X WSM\n");
  wsm = Dot3_ConstructWSM(&wsm_params, wsdu, wsdu_size, &wsm_size, &ret);
  if (wsm == NULL) {
    Err("Fail to construct C-V2X WSM - Dot3_ConstructWSM() failed - %d\n", ret);
    goto clear;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d-bytes C-V2X WSM\n", wsm_size);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, wsm, wsm_size);

  /*
   * WSM을 전송한다.
   */
#if defined(_LTEV2X_HAL_)
  struct LTEV2XHALTxFlowParams tx_flow;
  bool is_event;
  if (g_tcia_mib.flow_info[wsm_tx_info->flow_id].type == kLTEV2XHALTxFlowType_SPS) {
    memset(&tx_flow, 0x00, sizeof(struct LTEV2XHALTxFlowParams));
    ret = LTEV2XHAL_RetrieveTransmitFlow(g_tcia_mib.flow_info[wsm_tx_info->flow_id].index, &tx_flow);
    if (ret < 0) {
      Err("Fail to retrieve transmit flow - LTEV2XHAL_RetrieveTransmitFlow() failed: %d\n", ret);
      goto clear;
    }
  }
  is_event = (tx_flow.interval == kLTEV2XHALTxFLowInterval_None && tx_flow.priority == kLTEV2XHALPriority_None && tx_flow.size == kLTEV2XHALMSDUSize_None);

  struct LTEV2XHALMSDUTxParams tx_params;
  memset(&tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
  tx_params.tx_flow_type = (is_event == true ? kLTEV2XHALTxFlowType_Ad_Hoc : g_tcia_mib.flow_info[wsm_tx_info->flow_id].type);
  tx_params.tx_flow_index = g_tcia_mib.flow_info[wsm_tx_info->flow_id].index;
  tx_params.priority = g_tcia_mib.flow_info[wsm_tx_info->flow_id].pppp;
  tx_params.tx_power = g_tcia_mib.flow_info[wsm_tx_info->flow_id].power;
  tx_params.dst_l2_id = (wsm_tx_info->dst_mac_addr[5] << 16) | (wsm_tx_info->dst_mac_addr[4] << 8) | (wsm_tx_info->dst_mac_addr[3]); // little endian
  ret = LTEV2XHAL_TransmitMSDU(wsm, wsm_size, tx_params);
  if (ret < 0) {
    Err("Fail to transmit MSDU - LTEV2XHAL_TransmitMSDU() failed: %d\n", ret);
    goto clear;
  }
#else
  struct LalMSDUTxParams lal_params;
  memset(&lal_params, 0, sizeof(lal_params));
  lal_params.psid = wsm_tx_info->psid;
  lal_params.chan_num = wsm_tx_info->chan_num;
  lal_params.tx_power = wsm_tx_info->tx_power;
  lal_params.priority = wsm_tx_info->priority;
  Log(kTCIA3LogLevel_DetailedEvent, "Transmit C-V2X WSM\n");
  ret = LAL_TransmitMSDU(wsm_tx_info->if_idx, wsm, wsm_size, &lal_params);
  if (ret < 0) {
    Err("Fail to transmit C-V2X WSM - LAL_TransmitMSDU() failed - %d\n", ret);
    goto clear;
  }
#endif

  ++(g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot]);
  if ((g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot] % 10) == 1) {
    Log(kTCIA3LogLevel_Event, "Success to send %u-th C-V2X WSM(psid: %d) MPDU on channel %d at timeslot %d\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot], wsm_tx_info->psid, wsm_tx_info->chan_num, timeslot);
  } else {
    Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-th C-V2X WSM(psid: %d) MPDU on channel %d at timeslot %d\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot], wsm_tx_info->psid, wsm_tx_info->chan_num, timeslot);
  }

  clear:
  if (wsm != NULL) {
    free(wsm);
  }
}


/**
 * @brief LTE-V2X를 이용하여 WSA를 전송한다.
 * @param[in] secured_wsa 전송할 WSA
 * @param[in] secured_wsa_size 전송할 WSA의 길이
 */
void TCIA2023_LTE_V2X_TransmitWSA(const uint8_t *secured_wsa, size_t secured_wsa_size)
{
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSATxInfo *wsa_tx_info = &(wsa_info->tx_info);

  int ret;
  size_t wsm_size = 0;
  uint8_t *wsm = NULL;

  /*
   * WSM을 생성한다.
   */
  struct Dot3WSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.psid = kDot3PSID_WSA;
  wsm_params.chan_num = kDot3ChannelNumber_NA;
  wsm_params.datarate = kDot3DataRate_NA;
  wsm_params.transmit_power = kDot3Power_NA;
  Log(kTCIA3LogLevel_DetailedEvent, "Construct C-V2X WSM\n");
  wsm = Dot3_ConstructWSM(&wsm_params, secured_wsa, secured_wsa_size, &wsm_size, &ret);
  if (wsm == NULL) {
    Err("Fail to construct C-V2X WSM - Dot3_ConstructWSM() failed: %d\n", ret);
    goto clear;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d-bytes C-V2X WSM\n", wsm_size);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, wsm, wsm_size);

  /*
   * WSM을 전송한다.
   */
#if defined(_LTEV2X_HAL_)
  struct LTEV2XHALTxFlowParams tx_flow;
  memset(&tx_flow, 0x00, sizeof(struct LTEV2XHALTxFlowParams));
  ret = LTEV2XHAL_RetrieveTransmitFlow(g_tcia_mib.flow_info[wsa_tx_info->flow_id].index, &tx_flow);
  if (ret < 0) {
    Err("Fail to retrieve transmit flow - LTEV2XHAL_RetrieveTransmitFlow() failed: %d\n", ret);
    goto clear;
  }
  bool is_event = (tx_flow.interval == kLTEV2XHALTxFLowInterval_None && tx_flow.priority == kLTEV2XHALPriority_None && tx_flow.size == kLTEV2XHALMSDUSize_None);

  struct LTEV2XHALMSDUTxParams tx_params;
  memset(&tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
  tx_params.tx_flow_type = (is_event == true ? kLTEV2XHALTxFlowType_Ad_Hoc : kLTEV2XHALTxFlowType_SPS);
  tx_params.tx_flow_index = g_tcia_mib.flow_info[wsa_tx_info->flow_id].index;
  tx_params.priority = g_tcia_mib.flow_info[wsa_tx_info->flow_id].pppp;
  tx_params.tx_power = g_tcia_mib.flow_info[wsa_tx_info->flow_id].power;
  tx_params.dst_l2_id = (wsa_tx_info->dst_mac_addr[5] << 16) | (wsa_tx_info->dst_mac_addr[4] << 8) | (wsa_tx_info->dst_mac_addr[3]); // little endian
  ret = LTEV2XHAL_TransmitMSDU(wsm, wsm_size, tx_params);
  if (ret < 0) {
    Err("Fail to transmit MSDU - LTEV2XHAL_TransmitMSDU() failed: %d\n", ret);
    goto clear;
  }
#else
  struct LalMSDUTxParams lal_params;
  memset(&lal_params, 0, sizeof(lal_params));
  lal_params.psid = kDot3PSID_WSA;
  lal_params.chan_num = wsa_tx_info->chan_num;
  lal_params.tx_power = wsa_tx_info->tx_power;
  lal_params.priority = wsa_tx_info->priority;
  Log(kTCIA3LogLevel_DetailedEvent, "Transmit C-V2X WSM\n");
  ret = LAL_TransmitMSDU(wsa_tx_info->if_idx, wsm, wsm_size, &lal_params);
  if (ret < 0) {
    Err("Fail to transmit C-V2X WSM - LAL_TransmitMSDU() failed - %d\n", ret);
    goto clear;
  }
#endif

  ++(g_tcia_mib.testing.pkt_cnt.tx_wsa);
  if ((g_tcia_mib.testing.pkt_cnt.tx_wsa % 10) == 1) {
    Log(kTCIA3LogLevel_Event, "Success to send %u-th LTE-V2X WSA on channel %u at timeslot %u\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsa, wsa_tx_info->chan_num, wsa_tx_info->timeslot);
  } else {
    Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-th LTE-V2X WSA on channel %u at timeslot %u\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsa, wsa_tx_info->chan_num, wsa_tx_info->timeslot);
  }

  clear:
  if (wsm != NULL) {
  free(wsm);
  }
}

#if defined(_LTEV2X_HAL_)
/**
 * @brief LTE-V2X 이용하여 BSM을 전송한다.
 * @param[in] secured_bsm 전송할 BSM
 * @param[in] secured_bsm_size 전송할 BSM 길이
 * @param[in] timeslot 전송 TimeSlot
 */
void TCIA2023_LTE_V2X_TransmitBSM(const uint8_t *secured_bsm, size_t secured_bsm_size, Dot3TimeSlot timeslot, bool event)
{
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);

  int ret;
  size_t wsm_size = 0;
  uint8_t *wsm = NULL;

  /*
   * WSM을 생성한다.
   */
  struct Dot3WSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.chan_num = (wsm_tx_info->chan_num_ext == true) ? 183 : kDot3ChannelNumber_NA;
  wsm_params.datarate = (wsm_tx_info->datarate_ext == true) ? 12 : kDot3DataRate_NA;
  wsm_params.transmit_power = (wsm_tx_info->txpower_ext == true) ? 20 : kDot3Power_NA;
  wsm_params.psid = wsm_tx_info->psid;
  Log(kTCIA3LogLevel_DetailedEvent, "Construct C-V2X WSM\n");
  wsm = Dot3_ConstructWSM(&wsm_params, secured_bsm, secured_bsm_size, &wsm_size, &ret);
  if (wsm == NULL) {
    Err("Fail to construct C-V2X WSM - Dot3_ConstructWSM() failed - %d\n", ret);
    goto clear;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d-bytes C-V2X WSM\n", wsm_size);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, wsm, wsm_size);

  /*
   * WSM을 전송한다.
   */
  struct LTEV2XHALTxFlowParams tx_flow;
  memset(&tx_flow, 0x00, sizeof(struct LTEV2XHALTxFlowParams));
  ret = LTEV2XHAL_RetrieveTransmitFlow(g_tcia_mib.flow_info[wsm_tx_info->flow_id].index, &tx_flow);
  if (ret < 0) {
    Err("Fail to retrieve transmit flow - LTEV2XHAL_RetrieveTransmitFlow() failed: %d\n", ret);
    goto clear;
  }
  bool is_event = (tx_flow.interval == kLTEV2XHALTxFLowInterval_None && tx_flow.priority == kLTEV2XHALPriority_None && tx_flow.size == kLTEV2XHALMSDUSize_None);

  struct LTEV2XHALMSDUTxParams tx_params;
  memset(&tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
  tx_params.tx_flow_type = (is_event == true ? kLTEV2XHALTxFlowType_Ad_Hoc : kLTEV2XHALTxFlowType_SPS);
  tx_params.tx_flow_index = g_tcia_mib.flow_info[wsm_tx_info->flow_id].index;
  tx_params.priority = (event == true ? 2 - 1 /* Critical event 발생 */ : g_tcia_mib.flow_info[wsm_tx_info->flow_id].pppp - 1); // Pc5SL-Priority 범위가 1씩 차이나므로 1씩 차감
  tx_params.tx_power = g_tcia_mib.flow_info[wsm_tx_info->flow_id].power;
  tx_params.dst_l2_id = (wsm_tx_info->dst_mac_addr[5] << 16) | (wsm_tx_info->dst_mac_addr[4] << 8) | (wsm_tx_info->dst_mac_addr[3]); // little endian
  ret = LTEV2XHAL_TransmitMSDU(wsm, wsm_size, tx_params);
  if (ret < 0) {
    Err("Fail to transmit MSDU - LTEV2XHAL_TransmitMSDU() failed: %d\n", ret);
    goto clear;
  }


  ++(g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot]);
  if ((g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot] % 10) == 1) {
    Log(kTCIA3LogLevel_Event, "Success to send %u-th C-V2X WSM(psid: %d) MPDU on channel %d at timeslot %d\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot], wsm_tx_info->psid, wsm_tx_info->chan_num, timeslot);
  } else {
    Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-th C-V2X WSM(psid: %d) MPDU on channel %d at timeslot %d\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot], wsm_tx_info->psid, wsm_tx_info->chan_num, timeslot);
  }

  clear:
  if (wsm != NULL) {
    free(wsm);
  }
}
#endif


/**
 * @brief C-V2X MSDU 수신콜백함수
 * @param[in] msdu 수신된 MSDU 데이터
 * @param[in] msdu_size 수신된 MSDU 데이터 길이
 *
 * 다음 동작을 수행한다\n
 *  - MSDU가 수신되면 접속계층라이브러리에 의해 호출된다.\n
 *  - TCI indication 메시지를 생성하여 TS로 전송한다.\n
 */
#if defined(_LTEV2X_HAL_)
void TCIA2023_LTE_V2X_ProcessRxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_params)
#else
void TCIA2023_LTE_V2X_ProcessRxMSDUCallback(const uint8_t *msdu, size_t msdu_size)
#endif
{
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_DetailedEvent) {
    Log(kTCIA3LogLevel_DetailedEvent, "Proces %u-bytes rx C-V2X MSDU\n", msdu_size);
    TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, msdu, msdu_size);
  }

  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateCV2XPacketParseData(msdu, msdu_size);
  if (parsed == NULL) {
    Err("Fail to process rx C-V2X MSDU - V2X_AllocateCV2XPacketParseData() failed\n");
    return;
  }

  /*
   * 수신 파라미터를 mac_wsm에 저장
   */
  parsed->mac_wsm.mac.priority = rx_params.rx_priority;
  parsed->mac_wsm.mac.src_mac_addr[3] = ((uint8_t *) &rx_params.src_l2_id)[1];
  parsed->mac_wsm.mac.src_mac_addr[4] = ((uint8_t *) &rx_params.src_l2_id)[2];
  parsed->mac_wsm.mac.src_mac_addr[5] = ((uint8_t *) &rx_params.src_l2_id)[3];
  parsed->mac_wsm.mac.dst_mac_addr[3] = ((uint8_t *) &rx_params.dst_l2_id)[1];
  parsed->mac_wsm.mac.dst_mac_addr[4] = ((uint8_t *) &rx_params.dst_l2_id)[2];
  parsed->mac_wsm.mac.dst_mac_addr[5] = ((uint8_t *) &rx_params.dst_l2_id)[3];

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
    Err("Fail to process rx C-V2X MSDU - Dot3_ParseWSMMPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
  struct Dot3MACAndWSMParseParams *mac_wsm_parsed = &(parsed->mac_wsm);

  /*
   * 수신된 WSM의 PSID에 해당되는 시간슬롯을 확인한다.
   */
  Dot3TimeSlot timeslot;
#if defined(_TCIA2023_DSRC_)
  if (mac_wsm_parsed->wsm.psid == g_tcia_mib.wsm_trx_info[0].psid) {
    timeslot = kDot3TimeSlot_0;
  } else if (mac_wsm_parsed->wsm.psid == g_tcia_mib.wsm_trx_info[1].psid) {
    timeslot = kDot3TimeSlot_1;
  } else if (mac_wsm_parsed->wsm.psid == g_tcia_mib.wsm_trx_info[2].psid) {
    timeslot = kDot3TimeSlot_Continuous;
  } else {
    timeslot = kDot3TimeSlot_Continuous;
    Err("Fail to process received C-V2X MSDU - cannot find timeslot(%u,%u,%u) for psid %u\n",
        g_tcia_mib.wsm_trx_info[0].psid,  g_tcia_mib.wsm_trx_info[1].psid,  g_tcia_mib.wsm_trx_info[2].psid,
        mac_wsm_parsed->wsm.psid);
    return;
  }
#elif defined(_TCIA2023_LTE_V2X_)
  timeslot = kDot3TimeSlot_Continuous;
#endif
  /*
   * 로그 출력
   */
  (g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot])++;
  if ((g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot] % 10) == 1) {
    Log(kTCIA3LogLevel_Event, "%u-th WSM(psid: %d) is received at timeslot[%u]\n",
        g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot], mac_wsm_parsed->wsm.psid, timeslot);
  } else {
    Log(kTCIA3LogLevel_DetailedEvent, "%u-th WSM(psid: %d) is received at timeslot[%u]\n",
        g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot], mac_wsm_parsed->wsm.psid, timeslot);
  }

  /*
   * SPDU를 처리한다 - 결과는 콜백함수를 통해 전달된다.
   */
  struct Dot2SPDUProcessParams params;
  memset(&params, 0, sizeof(params));
  params.rx_psid = parsed->mac_wsm.wsm.psid;
  params.rx_pos.lat = g_tcia_mib.input_params.lat;
  params.rx_pos.lon = g_tcia_mib.input_params.lon;
  ret = Dot2_ProcessSPDU(parsed->wsdu, parsed->wsdu_size, &params, parsed);
  if (ret < 0) {
    Err("Fail to process received C-V2X MSDU - Dot2_ProcessSPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
}
