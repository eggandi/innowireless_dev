/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


// 시스템 헤더 파일
#include <signal.h>

// 라이브러리 헤더 파일
#include "wlanaccess/wlanaccess.h"
#include "j29451/j29451.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief DSRC WSM을 생성하여 전송한다.
 * @param[in] wsdu WSM에 수납될 WSDU
 * @param[in] wsdu_size WSM에 수납될 WSDU의 길이
 * @param[in] timeslot 전송 TimeSlot
 */
void TCIA2023_DSRC_TransmitWSM(const uint8_t *wsdu, size_t wsdu_size, Dot3TimeSlot timeslot)
{
  struct TCIA3WSMTrxInfo *wsm_tx_info = &(g_tcia_mib.wsm_trx_info[timeslot]);

  /*
   * WSM MPDU를 생성한다.
   */
  int ret;
  struct Dot3MACAndWSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.wsm.chan_num = (wsm_tx_info->chan_num_ext == true) ? wsm_tx_info->chan_num : kDot3ChannelNumber_NA;
  wsm_params.wsm.datarate = (wsm_tx_info->datarate_ext == true) ? wsm_tx_info->datarate : kDot3DataRate_NA;
  wsm_params.wsm.transmit_power = (wsm_tx_info->txpower_ext == true) ? wsm_tx_info->tx_power : kDot3Power_NA;
  wsm_params.wsm.psid = wsm_tx_info->psid;
  wsm_params.mac.priority = wsm_tx_info->priority;
  memset(wsm_params.mac.dst_mac_addr, 0xff, MAC_ALEN);
  memcpy(wsm_params.mac.src_mac_addr, g_tcia_mib.v2x_if.mac_addr[wsm_tx_info->if_idx], MAC_ALEN);
  Log(kTCIA3LogLevel_DetailedEvent, "Construct WAVE WSM MPDU\n");
  size_t mpdu_size;
  uint8_t *mpdu = Dot3_ConstructWSMMPDU(&wsm_params, wsdu, wsdu_size, &mpdu_size, &ret);
  if (mpdu == NULL) {
    Err("Fail to construct WAVE WSM MPDU - Dot3_ConstructWSMMPDU() failed - %d\n", ret);
    return;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d-bytes WAVE WSM MPDU\n", mpdu_size);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, mpdu, mpdu_size);

  /*
   * WSM MPDU를 전송한다.
   */
  struct WalMPDUTxParams wal_params;
  memset(&wal_params, 0, sizeof(wal_params));
  wal_params.chan_num = wsm_tx_info->chan_num;
  wal_params.datarate = wsm_tx_info->datarate;
  wal_params.expiry = 0;
  wal_params.tx_power = wsm_tx_info->tx_power;
  Log(kTCIA3LogLevel_DetailedEvent, "Transmit WAVE WSM MPDU\n");
  ret = WAL_TransmitMPDU(wsm_tx_info->if_idx, mpdu, mpdu_size, &wal_params);
  if (ret < 0) {
    Err("Fail to transmit WAVE WSM MPDU - WAL_TransmitMPDU() failed - %d\n", ret);
  }
  else {
    ++(g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot]);
    if ((g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot] % 10) == 1) {
      Log(kTCIA3LogLevel_Event, "Success to send %u-th WAVE WSM(psid: %d) MPDU on channel %d at timeslot %d\n",
          g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot], wsm_tx_info->psid, wsm_tx_info->chan_num, timeslot);
    }
    else {
      Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-th WAVE WSM(psid: %d) MPDU on channel %d at timeslot %d\n",
          g_tcia_mib.testing.pkt_cnt.tx_wsm[timeslot], wsm_tx_info->psid, wsm_tx_info->chan_num, timeslot);
    }
  }

  free(mpdu);
}


/**
 * @brief DSRC를 이용하여 WSA를 전송한다.
 * @param[in] secured_wsa 전송할 WSA
 * @param[in] secured_wsa_size 전송할 WSA의 길이
 */
void TCIA2023_DSRC_TransmitWSA(const uint8_t *secured_wsa, size_t secured_wsa_size)
{
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  struct TCIA3WSATxInfo *wsa_tx_info = &(wsa_info->tx_info);

  /*
   * WSM MPDU를 생성한다.
   */
  Log(kTCIA3LogLevel_DetailedEvent, "Construct WSM MPDU\n");
  struct Dot3MACAndWSMConstructParams wsm_params;
  memset(&wsm_params, 0, sizeof(wsm_params));
  wsm_params.wsm.psid = kDot3PSID_WSA;
  wsm_params.mac.priority = wsa_tx_info->priority;
  wsm_params.wsm.datarate = kDot3DataRate_NA;
  memcpy(wsm_params.mac.dst_mac_addr, wsa_tx_info->dst_mac_addr, MAC_ALEN);
  memcpy(wsm_params.mac.src_mac_addr, g_tcia_mib.v2x_if.mac_addr[wsa_tx_info->if_idx], MAC_ALEN);
  int ret;
  size_t mpdu_size;
  uint8_t *mpdu = Dot3_ConstructWSMMPDU(&wsm_params, secured_wsa, secured_wsa_size, &mpdu_size, &ret);
  if (mpdu == NULL) {
    Err("Fail to construct WSM MPDU - Dot3_ConstructWSMMPDU() failed - %d\n", mpdu_size);
    return;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d-bytes WSM MPDU\n", mpdu_size);

  /*
   * WSM MPDU를 전송한다.
   */
  struct WalMPDUTxParams wal_params;
  memset(&wal_params, 0, sizeof(wal_params));
  wal_params.chan_num = wsa_tx_info->chan_num;
  wal_params.datarate = wsa_tx_info->datarate;
  wal_params.expiry = 0;
  wal_params.tx_power = wsa_tx_info->tx_power;
  Log(kTCIA3LogLevel_DetailedEvent, "Transmit %u bytes WSA MPDU\n", mpdu_size);
  ret = WAL_TransmitMPDU(wsa_tx_info->if_idx, mpdu, mpdu_size, &wal_params);
  if (ret < 0) {
    Err("Fail to transmit WSA MPDU - WAL_TransmitMPDU() failed - %d\n", ret);
  } else {
    ++(g_tcia_mib.testing.pkt_cnt.tx_wsa);
    Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-th WSA MPDU on channel %u at timeslot %u\n",
        g_tcia_mib.testing.pkt_cnt.tx_wsa, wsa_tx_info->chan_num, wsa_tx_info->timeslot);
  }

  free(mpdu);
}


/**
 * @brief DSRC MPDU 수신콜백함수
 * @param[in] mpdu 수신된 MPDU 데이터
 * @param[in] mpdu_size 수신된 MPDU 데이터 길이
 * @param[in] rx_params 수신 파라미터 정보
 *
 * 다음 동작을 수행한다\n
 *  - MPDU가 수신되면 접속계층라이브러리에 의해 호출된다.\n
 *  - TCI indication 메시지를 생성하여 TS로 전송한다.\n
 */
void TCIA2023_DSRC_ProcessRxMPDUCallback(
  const uint8_t *mpdu,
  WalMPDUSize mpdu_size,
  const struct WalMPDURxParams *mpdu_rx_params)
{
  uint8_t ind_pkt[TCI_MSG_MAX_SIZE];
  int ind_pkt_size;

  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_DetailedEvent) {
    Log(kTCIA3LogLevel_DetailedEvent, "Proces %u-bytes rx MPDU\n", mpdu_size);
    TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, mpdu, mpdu_size);
  }

  /*
   * 패킷파싱데이터를 할당한다.
   */
  struct V2XPacketParseData *parsed = V2X_AllocateDSRCPacketParseData(mpdu, mpdu_size, mpdu_rx_params);
  if (parsed == NULL) {
    Err("Fail to process rx MPDU - V2X_AllocateDSRCPacketParseData() failed\n");
    return;
  }

  /*
   * WSM MPDU를 파싱한다.
   */
  int ret;
  parsed->wsdu = Dot3_ParseWSMMPDU(parsed->pkt,
                                   parsed->pkt_size,
                                   &(parsed->mac_wsm),
                                   &(parsed->wsdu_size),
                                   &(parsed->interested_psid),
                                   &ret);
  if (parsed->wsdu == NULL) {
    Err("Fail to process rx MPDU - Dot3_ParseWSMMPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
  struct Dot3MACAndWSMParseParams *mac_wsm_parsed = &(parsed->mac_wsm);

  /*
   * 수신된 WSM의 PSID에 해당되는 시간슬롯을 확인한다.
   */
  Dot3TimeSlot timeslot;
  if (mac_wsm_parsed->wsm.psid == g_tcia_mib.wsm_trx_info[0].psid) {
    timeslot = kDot3TimeSlot_0;
  } else if (mac_wsm_parsed->wsm.psid == g_tcia_mib.wsm_trx_info[1].psid) {
    timeslot = kDot3TimeSlot_1;
  } else if (mac_wsm_parsed->wsm.psid == g_tcia_mib.wsm_trx_info[2].psid) {
    timeslot = kDot3TimeSlot_Continuous;
  } else {
    Err("Fail to process received WSM MPDU - cannot find timeslot(%u,%u,%u) for psid %u\n",
        g_tcia_mib.wsm_trx_info[0].psid, g_tcia_mib.wsm_trx_info[1].psid, g_tcia_mib.wsm_trx_info[2].psid,
        mac_wsm_parsed->wsm.psid);
    return;
  }

  /*
   * 로그 출력
   */
  (g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot])++;
  if ((g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot] % 10) == 1) {
    Log(kTCIA3LogLevel_Event, "%u-th WSM(psid: %d) is received on channel %d at timeslot: %d\n",
        g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot], mac_wsm_parsed->wsm.psid, mpdu_rx_params->chan_num, timeslot);
  } else {
    Log(kTCIA3LogLevel_DetailedEvent, "%u-th WSM(psid: %d) is received on channel %d at timeslot %d\n",
        g_tcia_mib.testing.pkt_cnt.rx_wsm[timeslot], mac_wsm_parsed->wsm.psid, mpdu_rx_params->chan_num, timeslot);
  }

  /*
   * 802.11 시험인 경우, dot2 메시지 처리를 하지 않고 바로 Indication 한다. (TS에서 전송하는 패킷이 dot2 메시지가 아닐 수 있다)
   */
  if (g_tcia_mib.testing.test_protocol == kTCIA3TestProtocol_80211) {
    ind_pkt_size = TCIA2023_ConstructIndication(mpdu,
                                            mpdu_size,
                                            parsed->wsm, // 802.11 indication에서는 사용하지 않음
                                            parsed->wsm_size, // 802.11 indication에서는 사용하지 않음
                                            mpdu_rx_params,
                                            &(parsed->mac_wsm),
                                            NULL, // 802.11 indication에서는 사용하지 않음
                                            kCvcoctci2023SecurityResultCode_Success, // 802.11 indication에서는 사용하지 않음
                                            ind_pkt,
                                            sizeof(ind_pkt));
    if (ind_pkt_size > 0) {
      TCIA2023_SendTCIMessagePacket(ind_pkt, ind_pkt_size);
    }
    V2X_FreePacketParseData(parsed);
    return;
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
    Err("Fail to process rx MPDU - Dot2_ProcessSPDU() failed: %d\n", ret);
    V2X_FreePacketParseData(parsed);
    return;
  }
}


/**
 * @brief DSRC 통신 인터페이스를 특정 채널에 접속한다.
 * @param[in] if_idx 인터페이스 식별번호
 * @param[in] ts0_chan TimeSlot0 채널번호
 * @param[in] ts1_chan TimeSlot1 채널번호
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_DSRC_AccessChannel(unsigned int if_idx, WalChannelNumber ts0_chan, WalChannelNumber ts1_chan)
{
  Log(kTCIA3LogLevel_Event, "Access channel(%u-%u) on if[%u]\n", ts0_chan, ts1_chan, if_idx);
  int ret = WAL_AccessChannel(if_idx, ts0_chan, ts1_chan);
  if (ret < 0) {
    Err("Fail to access channel - WAL_AccessChannel() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to access channel\n");
  return 0;
}


/**
 * @brief V2X 인터페이스들의 초기 MAC 주소를 설정한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_DSRC_SetInitialIfMACAddress(void)
{
  Log(kTCIA3LogLevel_Init, "Set V2X interface initial MAC address\n");

  int ret;
  for(unsigned int if_idx = 0; if_idx < g_tcia_mib.v2x_if.if_num; if_idx++)
  {
    Log(kTCIA3LogLevel_Init, "Set MAC address for if[%u]\n", if_idx);
    ret = WAL_ConvertMACAddressStrToOctets(g_tcia_mib.input_params.mac_addr[if_idx], g_tcia_mib.v2x_if.mac_addr[if_idx]);
    if (ret < 0) {
      Err("Fail to WAL_ConvertMACAddressStrToOctets() - %d\n", ret);
      return -1;
    }
    ret = WAL_SetIfMACAddress(if_idx, g_tcia_mib.v2x_if.mac_addr[if_idx]);
    if (ret < 0) {
      Err("Fail to set MAC address for if[%u] - %d\n", if_idx, ret);
      return -1;
    }
    Log(kTCIA3LogLevel_Init, "Success to set MAC address for if[%u] - "MAC_ADDR_FMT"\n",
        if_idx, MAC_ADDR_FMT_ARGS(g_tcia_mib.v2x_if.mac_addr[if_idx]));
  }

  Log(kTCIA3LogLevel_Init, "Success to set initial MAC address for %u interfaces\n", g_tcia_mib.v2x_if.if_num);
  return 0;
}
