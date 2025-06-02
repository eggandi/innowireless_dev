/**
 * @file
 * @brief TCI16093DSRC 메시지를 처리하는 기능을 구현한 파일
 * @date 2019-09-26
 * @author gyun
 */

// 시스템 헤더 파일
#include <stdio.h>
#include <string.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "wlanaccess/wlanaccess.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief 1609.3 dsrc SetInitialState 메시지를 처리한다.
 * @param[in] data SetInitialState 값
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCSetInitialState(bool data)
{
  return TCIA2023_ProcessSetInitialState(data);
}


/**
 * @brief 1609.3 dsrc SetWsmTxInfo 메시지를 처리한다.
 * @param[in] data SetWsmTxInfo 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCSetWsmTxInfo(const struct Cvcoctci2023SetWsmTxInfo *data)
{
  return TCIA2023_ProcessSetWsmTxInfo(data);
}


/**
 * @brief 1609.3 dsrc StartWsmTx 메시지를 처리한다.
 * @param[in] data StartWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @param[in] pdu TS 가 전송한 PDU
 * @param[in] pdu_size pdu 의 길이
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCStartWsmTx(const struct Cvcoctci2023StartWsmTx *data, const uint8_t *pdu, size_t pdu_size)
{
  return TCIA2023_ProcessStartWsmTx(data, pdu, pdu_size);
}


/**
 * @brief 1609.3 dsrc StopWsmTx 메시지를 처리한다.
 * @param[in] params StopWsmTx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCStopWsmTx(const struct Cvcoctci2023StopWsmTx *data)
{
  return TCIA2023_ProcessStopWsmTx(data);
}


/**
 * @brief 1609.3 dsrc StartWsmRx 메시지를 처리한다.
 * @param[in] data StartWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCStartWsmRx(const struct Cvcoctci2023StartWsmRx *data)
{
  return TCIA2023_ProcessStartWsmRx(data);
}


/**
 * @brief 1609.3 dsrc StopWsmRx 메시지를 처리한다.
 * @param[io] params StopWsmRx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCStopWsmRx(const struct Cvcoctci2023StopWsmRx *data)
{
  return TCIA2023_ProcessStopWsmRx(data);
}


/**
 * @brief TCI 메시지 내 EdcaParameterRecord 내용(ASN.1 context)을 로컬 정보로 변환한다.
 * @param[in] from TCI 메시지 내 EdcaParameterRecord
 * @param[out] to 변환된 정보가 반환된다.
 */
static void
TCIA2023_Process16093DSRCEdcaParameterRecord(const struct Cvcoctci2023EdcaParameterRecord *from, struct Dot3EDCAParameterRecord *to)
{
  to->aci = from->aci;
  to->acm = from->acm;
  to->aifsn = from->aifsn;
  to->ecwmin = from->ecwmin;
  to->ecwmax = from->ecwmax;
  to->txoplimit = from->txoplimit;
}


/**
 * @brief TCI 메시지 내 EdcaParameterSet 내용(ASN.1 context)을 로컬 정보로 변환한다.
 * @param[in] from TCI 메시지 내 EdcaParameterSet
 * @param[out] to 변환된 정보가 반환된다.
 */
static void
TCIA2023_Process16093DSRCEdcaParameterSet(const struct Cvcoctci2023EdcaParameterSet *from, struct Dot3EDCAParameterSet *to)
{
  TCIA2023_Process16093DSRCEdcaParameterRecord(&(from->ac_be), &(to->record[kDot3ACI_BE]));
  TCIA2023_Process16093DSRCEdcaParameterRecord(&(from->ac_bk), &(to->record[kDot3ACI_BK]));
  TCIA2023_Process16093DSRCEdcaParameterRecord(&(from->ac_vi), &(to->record[kDot3ACI_VI]));
  TCIA2023_Process16093DSRCEdcaParameterRecord(&(from->ac_vo), &(to->record[kDot3ACI_VO]));
}


/**
 * Update TCIv3 by young@KETI
 * wsa_chan_id, chan_access and repeat_rate change to OPTIONAL
 * 
 * @brief 수신된 StartWsaTxPeriodic 메시지의 내용으로 WSA 정보를 업데이트한다.
 * @param[in] from  수신된 StartWsaTxPeriodic
 * @param[out] to WSA 정보가 저장된다.
 */
static void TCIA2023_UpdateWsaInfo(const struct Cvcoctci2023StartWsaTxPeriodic *data, struct TCIA3WSAInfo *wsa_info)
{
  struct TCIA3WSATxInfo *tx_info = &(wsa_info->tx_info);
  tx_info->if_idx = data->radio.radio;
  if (true == data->options.wsa_chan_id) { tx_info->chan_num = data->wsa_chan_id; }
  // 스택에서의 TimeSlot 은 0부터 시작하고, TCI 에서는 1부터 시작한다.
  if (true == data->options.chan_access) { tx_info->timeslot = data->chan_access - 1; }
  if (true == data->options.repeat_rate) { tx_info->repeat_rate = data->repeat_rate; }
  if (true == data->options.dst_mac_addr) { memcpy(tx_info->dst_mac_addr, data->dst_mac_addr, MAC_ALEN); }
  if (true == data->options.datarate) { tx_info->datarate = data->datarate; }
  if (true == data->options.priority) { tx_info->priority = data->priority; }
  if (true == data->options.transmit_power_level) { tx_info->tx_power = data->transmit_power_level; }
  if (true == data->options.flow_id) {tx_info->flow_id = data->flow_id; }

  struct TCIA3WSAHdrInfo *hdr_info = &(wsa_info->hdr_info);
  if (true == data->info_elements_included.advertiser_id) {
    if (true == data->options.advertiser_id) {
      hdr_info->options.advertiser_id = true;
      memcpy(&(hdr_info->advertiser_id), &(data->advertiser_id), sizeof(data->advertiser_id));
    }
  }
  if (true == data->info_elements_included.repeat_rate) {
    if (true == data->options.repeat_rate) {
      hdr_info->options.repeat_rate = true;
      hdr_info->repeat_rate = data->repeat_rate;
    }
  }
  hdr_info->options.twod_location = data->info_elements_included.twod_location;
  hdr_info->options.threed_location = data->info_elements_included.threed_location;

  struct TCIA3WSASecurityInfo *sec_info = &(wsa_info->sec_info);
  sec_info->content_type = data->security.content_type;
  sec_info->signer_id_type = data->security.signer_id_type;
}


/**
 * @brief 수신된 StartWsaTxPeriodic 메시지의 내용으로 PCI들을 업데이트한다.
 * @param[in] data 수신된 StartWsaTxPeriodic 내 ChannelInfos 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_UpdatePcis(const struct Cvcoctci2023ChannelInfos *data)
{
  Log(kTCIA3LogLevel_Event, "Updating %u PCIs\n", data->cnt);

  struct Dot3PCI pci;
  const struct Cvcoctci2023ChannelInfo *cinfo;
  for (size_t i = 0; i < data->cnt; i++)
  {
    cinfo = &(data->info[i]);
    memset(&pci, 0, sizeof(pci));
    pci.operating_class = cinfo->op_class;
    pci.chan_num = cinfo->chan_num;
    pci.transmit_power_level = cinfo->power_level;
    pci.datarate = cinfo->datarate;
    pci.adaptable_datarate = cinfo->adaptable_datarate;
    if (cinfo->options.exts) {
      const struct Cvcoctci2023ChannelInfoExts *exts = &(cinfo->exts);
      if (exts->options.edca_param_set) {
        pci.present.edca_param_set = true;
        TCIA2023_Process16093DSRCEdcaParameterSet(&(exts->edca_param_set), &(pci.edca_param_set));
      }
      if (exts->options.chan_access) {
        pci.present.chan_access = true;
        pci.chan_access = exts->chan_access;
      }
    }
    Log(kTCIA3LogLevel_Event, "[%zu] Updating PCI - op_class:%d, chan:%d, txpower:%d, datarate:%d(%u), omit exts\n",
      i, pci.operating_class, pci.chan_num, pci.transmit_power_level, pci.datarate, pci.adaptable_datarate);
    int ret = Dot3_SetPCI(&pci);
    if (ret < 0) {
      Err("Fail to set PCI - ret: %d\n", ret);
      return -1;
    }
  }
  Log(kTCIA3LogLevel_Event, "Success to add PCIs\n");
  return 0;
}


/**
 * @brief 수신된 StartWsaTxPeriodic 메시지의 내용으로 PSR 들을 등록한다.
 * @param[in] data 수신된 StartWsaTxPeriodic 내 ServiceInfos 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_AddPsrs(const struct Cvcoctci2023ServiceInfos *data, const struct Cvcoctci2023ChannelInfos *chan_infos)
{
  Log(kTCIA3LogLevel_Event, "Adding %u PSRs\n", data->cnt);

  struct Dot3PSR psr;
  const struct Cvcoctci2023ServiceInfo *service_info;
  for (size_t i = 0; i < data->cnt; i++) {
    service_info = &(data->info[i]);
    memset(&psr, 0, sizeof(psr));
    psr.wsa_id = 0;
    psr.psid = service_info->psid;

    /**
     * Update TCIv3 by young@KETI
     * 수정 필요
     * */
    psr.service_chan_num = chan_infos->info[service_info->chan_idx - 1].chan_num;
    if (service_info->options.exts) {
      const struct Cvcoctci2023ServiceInfoExts *exts = &(service_info->exts);
      if (exts->options.psc) {
        psr.present.psc = true;
        psr.psc.len = exts->psc.len;
        memcpy(psr.psc.psc, exts->psc.psc, psr.psc.len);
      }
      if (exts->options.ipv6_addr) {
        psr.ip_service = true;
        memcpy(psr.ipv6_address, exts->ipv6_addr, IPv6_ALEN);
      }
      if (exts->options.service_port) {
        psr.service_port = exts->service_port;
      }
      if (exts->options.provider_mac_addr) {
        psr.present.provider_mac_addr = true;
        memcpy(psr.provider_mac_addr, exts->provider_mac_addr, MAC_ALEN);
      }
      if (exts->options.rcpi_threshold) {
        psr.present.rcpi_threshold = true;
        psr.rcpi_threshold = exts->rcpi_threshold;
      }
      if (exts->options.wsa_cnt_threshold) {
        psr.present.wsa_cnt_threshold = true;
        psr.wsa_cnt_threshold  = exts->wsa_cnt_threshold;
      }
      if (exts->options.wsa_cnt_threshold_interval) {
        psr.present.wsa_cnt_threshold_interval = true;
        psr.wsa_cnt_threshold_interval = exts->wsa_cnt_threshold_interval;
      }
    }
    Log(kTCIA3LogLevel_Event, "[%zu] Adding PSR - wsa_id:%d, psid:%d, chan:%d\n",
        i, psr.wsa_id, psr.psid, psr.service_chan_num);
    int ret = Dot3_AddPSR(&psr);
    if (ret < 0) {
      Err("Fail to add PSR - ret: %d\n", ret);
      return -1;
    }
  }

  Log(kTCIA3LogLevel_Event, "Success to add PSRs\n");
  return 0;
}


/**
 * @brief 수신된 StartWsaTxPeriodic 메시지의 내용으로 WRA 정보를 업데이트한다.
 * @param[in] from 수신된 메시지 내 WRA 정보
 * @param[out] to WRA 정보가 반환된다.
 */
static void TCIA2023_UpdateWra(const struct Cvcoctci2023RoutingAdvertisement *from, struct TCIA3WRAInfo *to)
{
  Log(kTCIA3LogLevel_Event, "Updating WRA\n");
  to->options.wra = true;
  to->router_lifetime = from->router_lifetime;
  memcpy(to->ip_prefix, from->ip_prefix, IPv6_ALEN);
  to->ip_prefix_len = from->ip_prefix_len;
  memcpy(to->default_gw, from->default_gw, IPv6_ALEN);
  memcpy(to->primary_dns, from->primary_dns, IPv6_ALEN);
  if (from->options.exts) {
    const struct Cvcoctci2023RoutingAdvertisementExts *exts = &(from->exts);
    if (exts->options.second_dns) {
      to->options.secondary_dns = true;
      memcpy(to->secondary_dns, exts->secondary_dns, IPv6_ALEN);
    }
    if (exts->options.gw_mac_addr) {
      to->options.gw_mac_addr = true;
      memcpy(to->gw_mac_addr, exts->gw_mac_addr, MAC_ALEN);
    }
  }
}


/**
 * @brief 1609.3 dsrc StartWsaTxPeriodic 메시지를 처리한다.
 * @param[in] data StartWsaTxPeriodic 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * 주기적인 WSA 전송을 시작한다.
 */
static int TCIA2023_Process16093DSRCStartWsaTxPeriodic(const struct Cvcoctci2023StartWsaTxPeriodic *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC StartWsaTxPeriodic\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStartWsaTxPeriodic(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC StartWsaTxPeriodic - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * WSA 전송 정보를 업데이트한다.
   */
  TCIA2023_UpdateWsaInfo(data, &(g_tcia_mib.wsa_info));

  /*
   * PCI(Provider Channel Info)를 업데이트한다.
   */
  int ret = TCIA2023_UpdatePcis(&(data->chan_infos));
  if (ret < 0) {
    return -1;
  }

  /*
   * PSR(Provider Service Request)을 등록한다.
   */
  ret = TCIA2023_AddPsrs(&(data->service_infos), &(data->chan_infos));
  if (ret < 0) {
    return -1;
  }

  /*
   * WRA(WAVE Routing Advertisement)를 등록한다.
   */
  if (data->options.wra) {
    TCIA2023_UpdateWra(&(data->wra), &(g_tcia_mib.wsa_info.wra_info));
  }

#if defined(_TCIA2023_DSRC_)
  /*
   * WSA 전송 채널에 접속한다.
   *  WSA ChannelAccess(TimeSlot) 값에 따라 채널접속 형태가 결정된다.
   */
  int ts0_chan_num, ts1_chan_num;
  switch (data->chan_access) {
    case kCvcoctci2023TimeSlot_AltSlot0:
      ts0_chan_num = ts1_chan_num = g_tcia_mib.wsa_info.tx_info.chan_num;
      if (data->service_infos.cnt) {
        /**
         * Update TCIv3 by young@KETI
         * 수정 필요
         * */
        ts1_chan_num = data->chan_infos.info[data->service_infos.info[0].chan_idx - 1].chan_num;
      }
      break;
    case kCvcoctci2023TimeSlot_AltSlot1:
      ts0_chan_num = ts1_chan_num = g_tcia_mib.wsa_info.tx_info.chan_num;
      if (data->service_infos.cnt) {
        /**
         * Update TCIv3 by young@KETI
         * 수정 필요
         * */
        ts0_chan_num = data->chan_infos.info[data->service_infos.info[0].chan_idx - 1].chan_num;
        ts0_chan_num = data->service_infos.info[0].chan_idx;
      }
      break;
    case kCvcoctci2023TimeSlot_Continuous:
      ts0_chan_num = ts1_chan_num = g_tcia_mib.wsa_info.tx_info.chan_num;
      break;
    default:
      Err("Fail to process 16093DSRC StartWsaTxPeriodic - invalid WSA timeslot %d\n", data->chan_access);
      return -1;
  }
  ret = TCIA2023_DSRC_AccessChannel(g_tcia_mib.wsa_info.tx_info.if_idx, ts0_chan_num, ts1_chan_num);
  if (ret < 0) {
    return -1;
  }
#endif

  /*
   * WSA를 생성하여 저장한다.
   */
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  ret = TCIA2023_ConstructWSA(wsa_info->wsa);
  if (ret < 0) {
    return -1;
  }
  wsa_info->wsa_size = (size_t)ret;

  /*
   * WSA 송신을 시작한다.
   */
  ret = TCIA2023_StartWSATransmit();
  if (ret < 0) {
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC StartWsaTxPeriodic\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc StopWsaTxPeriodic 메시지를 처리한다.
 * @param[in] data StopWsaTxPeriodic 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSA 전송을 중지한다.
 */
static int TCIA2023_Process16093DSRCStopWsaTxPeriodic(const struct Cvcoctci2023StopWsaTxPeriodic *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC StopWsaTxPeriodic\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintStopWsaTxPeriodic(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC StopWsaTxPeriodic - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * WSA 송신을 중지한다.
   */
  TCIA2023_StopWSATransmit();

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC StopWsaTxPeriodic\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 수신된 ChangeWsaProviderService 메시지의 내용으로 PSR 들을 등록한다.
 * @param[in] data 수신된 ChangeWsaProviderService 내 ServiceInfos 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_UpdatePsrs(const struct Cvcoctci2023ServiceInfos *data)
{
  Log(kTCIA3LogLevel_Event, "Updating %u PSRs\n", data->cnt);

  int ret;
  const struct Cvcoctci2023ServiceInfo *sinfo;
  for (size_t i = 0; i < data->cnt; i++)
  {
    sinfo = &(data->info[i]);
    if (sinfo->options.exts) {
      const struct Cvcoctci2023ServiceInfoExts *exts = &(sinfo->exts);
      if (exts->options.psc) {
        Log(kTCIA3LogLevel_Event, "[%zu] Updating PSR - psid:%d, psc:%s\n", i, sinfo->psid, exts->psc.psc);
        ret = Dot3_ChangePSR(sinfo->psid, (const char *)exts->psc.psc);
        if (ret < 0) {
          Err("Fail to update PSR - ret: %d\n", ret);
          return -1;
        }
      }
    }
  }

  Log(kTCIA3LogLevel_Event, "Success to update PSRs\n");
  return 0;
}


/**
 * @brief 1609.3 dsrc ChangeWsaProviderService 메시지를 처리한다.
 * @param[in] data ChangeWsaProviderService 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSA 전송 중지 -> PSR 업데이트 -> WSA 전송 재개
 */
static int TCIA2023_Process16093DSRCChangeWsaProviderService(const struct Cvcoctci2023ChangeWsaProviderService *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC ChangeWsaProviderService\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintChangeWsaProviderService(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC ChangeWsaProviderService - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * WSA 송신을 중지한다.
   */
  TCIA2023_StopWSATransmit();

  /*
   * PSR 을 업데이트한다.
   */
  int ret = TCIA2023_UpdatePsrs(&(data->infos));
  if (ret < 0) {
    return -1;
  }

  /*
   * 변경된 WSA를 생성하여 저장한다.
   */
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  ret = TCIA2023_ConstructWSA(wsa_info->wsa);
  if (ret < 0) {
    return -1;
  }
  wsa_info->wsa_size = (size_t)ret;

  /*
   * WSA 송신을 시작한다.
   */
  ret = TCIA2023_StartWSATransmit();
  if (ret < 0) {
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC ChangeWsaProviderService\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 수신된 DelWsaProviderService 메시지의 내용으로 PSR 들을 등록한다.
 * @param[in] data 수신된 DelWsaProviderService 내 ServiceInfos 정보
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_DeletePsrs(const struct Cvcoctci2023ServiceInfos *data)
{
  Log(kTCIA3LogLevel_Event, "Deleting %u PSRs\n", data->cnt);

  int ret;
  const struct Cvcoctci2023ServiceInfo *sinfo;
  for (size_t i = 0; i < data->cnt; i++)
  {
    sinfo = &(data->info[i]);
    Log(kTCIA3LogLevel_Event, "[%zu] Deleting PSR - psid:%d\n", i, sinfo->psid);
    ret = Dot3_DeletePSR(sinfo->psid);
    if (ret < 0) {
      Err("Fail to delete PSR for psid %d - ret: %d\n", sinfo->psid, ret);
      return -1;
    }
  }
  Log(kTCIA3LogLevel_Event, "Success to delete PSRs\n");
  return 0;
}


/**
 * @brief 1609.3 dsrc DelWsaProviderService 메시지를 처리한다.
 * @param[in] data DelWsaProviderService 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 * WSA 전송 중지 -> PSR 삭제 -> WSA 전송 재개
 */
static int TCIA2023_Process16093DSRCDelWsaProviderService(const struct Cvcoctci2023DelWsaProviderService *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC DelWsaProviderService\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintDelWsaProviderService(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC DelWsaProviderService - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * WSA 송신을 중지한다.
   */
  TCIA2023_StopWSATransmit();

  /*
   * PSR 을 삭제한다.
   */
  int ret = TCIA2023_DeletePsrs(&(data->infos));
  if (ret < 0) {
    return -1;
  }

  /*
   * 변경된 WSA를 생성하여 저장한다.
   */
  struct TCIA3WSAInfo *wsa_info = &(g_tcia_mib.wsa_info);
  ret = TCIA2023_ConstructWSA(wsa_info->wsa);
  if (ret < 0) {
    return -1;
  }
  wsa_info->wsa_size = (size_t)ret;

  /*
   * WSA 송신을 시작한다.
   */
  ret = TCIA2023_StartWSATransmit();
  if (ret < 0) {
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC DelWsaProviderService\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc AddWsaProviderService 메시지를 처리한다.
 * @param[in] data AddWsaProviderService 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 *
 */
static int TCIA2023_Process16093DSRCAddWsaProviderService(const struct Cvcoctci2023AddWsaProviderService *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC AddWsaProviderService\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintAddWsaProviderService(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC AddWsaProviderService - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * WSA 송신을 중지한다.
   */
  TCIA2023_StopWSATransmit();

  /*
   * PSR 을 삭제한다.
   */
  int ret = TCIA2023_AddPsrs(&(data->infos), NULL);
  if (ret < 0) {
    return -1;
  }

  /*
   * WSA 송신을 시작한다.
   */
  ret = TCIA2023_StartWSATransmit();
  if (ret < 0) {
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC AddWsaProviderService\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc AddUserService 메시지를 처리한다.
 * @param[in] data AddUserService 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCAddUserService(const struct Cvcoctci2023AddUserService *data)
{
  Log(kTCIA3LogLevel_Event, "Process 16093DSRC AddUserService\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintAddUserService(data);
  }

  /*
   * 라디오 번호 지원 여부를 체크한다.
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC AddUserService - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * 시간슬롯별 WSM 수신 파라미터 정보를 업데이트한다.
   */
  struct TCIA3WSMTrxInfo *wsm_rx_info = &(g_tcia_mib.wsm_trx_info[0]);
  wsm_rx_info->psid = kDot3PSID_WSA;
  wsm_rx_info->if_idx = data->radio.radio;
  wsm_rx_info->timeslot = 0;
  memcpy(&(wsm_rx_info->event_handling), &(data->event_handling), sizeof(struct Cvcoctci2023EventHandling));

  /*
   * USR을 등록한다.
   */
  struct Dot3USR usr;
  memset(&usr, 0, sizeof(usr));
  usr.psid = data->psid;
  if (data->wsa_type == kCvcoctci2023WsaType_SecureWsa) {
    usr.wsa_type = kDot3WSAType_Secured;
  } else if (data->wsa_type == kCvcoctci2023WsaType_UnsecureWsa) {
    usr.wsa_type = kDot3WSAType_Unsecured;
  } else {
    Err("Fail to process 16093DSRC AddUserService - invalid WSA type\n", data->wsa_type);
    return -1;
  }
  
  /**
   * Update TCIv3 by young@KETI
   * Add psc, src_mac_addr, advertiser_id and chan_id
   * */
  if (true == data->options.psc) {
    usr.present.psc = true;
    usr.psc.len = data->psc.len;
    memcpy(usr.psc.psc, data->psc.psc, usr.psc.len);
  }
  if (true == data->options.src_mac_addr) {
    usr.present.src_mac_addr = true;
    memcpy(usr.src_mac_addr, data->src_mac_addr, MAC_ALEN);
  }
  if (true == data->options.advertiser_id) {
    usr.present.advertiser_id = true;
    usr.advertiser_id.len = data->advertiser_id.len;
    memcpy(usr.advertiser_id.id, data->advertiser_id.id, usr.advertiser_id.len);
  }
  if (true == data->options.chan_id) {
    usr.present.chan_num = true;
    usr.chan_num = data->chan_id;
  }

  int ret = Dot3_AddUSR(&usr);
  if (ret < 0) {
    Err("Fail to process 16093DSRC AddUserService - Dot3_AddUSR() failed: %d\n", ret);
    return -1;
  }
  Log(kTCIA3LogLevel_Event, "Success to add USR - psid: %u, WSA type: %u(1:unsec, 2:sec)\n", usr.psid, usr.wsa_type);

#if defined(_TCIA2023_DSRC_)
  /*
   * 앞으로의 WSA 수신을 위해 CCH에 접속한다.
   */
  ret = TCIA2023_DSRC_AccessChannel(data->radio.radio, kWalChannelNumber_CCH, kWalChannelNumber_CCH);
  if (ret < 0) {
    return ret;
  }
#endif

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC AddUserService\n");\
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc DelUserService 메시지를 처리한다.
 * @param[in] data DelUserService 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCDelUserService(const struct Cvcoctci2023DelUserService *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC DelUserService\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintDelUserService(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC DelUserService - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * WSA 수신을 종료한다.
   */
  TCIA2023_StopWSMReceive(kDot3TimeSlot_Continuous);

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC DelUserService\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc GetIPv6InterfaceInfo 메시지를 처리한다.
 * @param[in] data GetIPv6InterfaceInfo 파싱정보가 저장된 정보구조체 포인터
 * @param[out] radio_idx 인터페이스 정보를 요청하는 인터페이스 식별번호가 저장될 변수 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int
TCIA2023_Process16093DSRCGetIPv6InterfaceInfo(const struct Cvcoctci2023GetIPv6InterfaceInfo *data, Cvcoctci2023Radio *radio_idx)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC GetIPv6InterfaceInfo\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintGetIPv6InterfaceInfo(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC GetIPv6InterfaceInfo - not supported radio %d\n", data->radio.radio);
    return -1;
  }
  *radio_idx = data->radio.radio;

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC GetIPv6InterfaceInfo - idx: %d\n", *radio_idx);
  return kTCIA3ResponseMsgType_ResponseInterfaceInfo;
}


/**
 * @brief 1609.3 dsrc SetIPv6Address 메시지를 처리한다.
 * @param[in] data SetIPv6Address 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCSetIPv6Address(const struct Cvcoctci2023SetIPv6Address *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC SetIPv6Address\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintSetIPv6Address(data);
  }

  /*
   * 라디오 번호 지원 여부 체크
   */
  if (data->radio.radio >= (Cvcoctci2023Radio)(g_tcia_mib.v2x_if.if_num)) {
    Err("Fail to process 16093DSRC SetIPv6Address - not supported radio %d\n", data->radio.radio);
    return -1;
  }

  /*
   * IPv6 주소룰 설정한다.
   */
  int ret;
  if (data->options.ip_addr) {
#if defined(_TCIA2023_DSRC_)
    ret = WAL_SetIPv6Address(data->radio.radio, data->ip_addr, 64);
    if (ret < 0) {
      Err("Fail to process 16093DSRC SetIPv6Address - WAL_SetIPv6Address() failed: %d\n", ret);
      return -1;
    }
#endif
  }

  /*
   * TS가 IPv6 주소를 지정하지 않았으면, 모든 IPv6 주소를 삭제하고 랜덤한 새로운 링크로컬주소를 설정한다.
   */
  else {
    ret = TCIA2023_DeleteAllIPv6Address(data->radio.radio);
    if (ret < 0) {
      return -1;
    }
    ret = TCIA2023_SetRandomLinkLocalAddress(data->radio.radio);
    if (ret < 0) {
      return -1;
    }
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC SetIPv6Address\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc StartIPv6Tx 메시지를 처리한다.
 * @param[in] data StartIPv6Tx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCStartIPv6Ping(const struct Cvcoctci2023StartIPv6Tx *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC StartIPv6Ping\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintIPv6TxRecord(data);
  }

  /*
   * IP 전송 동작을 시작한다.
   */
  int ret = TCIA2023_StartPingTxOperation(data);
  if (ret < 0) {
    Err("Fail to process 16093DSRC StartIPv6Ping\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC StartIPv6Ping\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc StopIPv6Tx 메시지를 처리한다.
 * @param[in] params StopIPv6Tx 파싱정보가 저장된 정보구조체 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
static int TCIA2023_Process16093DSRCStopIPv6Ping(const struct Cvcoctci2023StopIPv6Tx *data)
{
  Log(kTCIA3LogLevel_Event, "Processing 16093DSRC StopIPv6Tx\n");
  if (g_tcia_mib.log.tcia >= kTCIA3LogLevel_Event) {
    Cvcoctci2023_PrintIPv6TxRecord(data);
  }

  /*
   * IP 전송 동작을 중지한다.
   */
  int ret = TCIA2023_StopIPv6TxOperation(data);
  if (ret < 0) {
    Err("Fail to process 16093DSRC StopIPV6Tx\n");
    return -1;
  }

  Log(kTCIA3LogLevel_Event, "Success to process 16093DSRC StopIPv6Tx\n");
  return kTCIA3ResponseMsgType_Response;
}


/**
 * @brief 1609.3 dsrc TCI Request 메시지를 처리한다.
 * @param[in] parse_params TCI 메시지 파싱 정보가 저장되어 있는 구조체 포인터
 * @param[in] pdu TCI 메시지 내에 수납되어 있는 pdu (수납되어 있지 않은 경우 NULL)
 * @param[in] pdu_size pdu 의 크기
 * @param[out] radio_idx Request 메시지가 GetIPv6InterfaceInfo 일 경우, 요청된 인터페이스 식별번호가 저장될 변수 포인터
 * @retval ResponseMsgType: 성공
 * @retval -1: 실패
 */
int TCIA2023_Process16093DSRCTCIMessage(
  const struct Cvcoctci2023Params *parse_params,
  const uint8_t *pdu,
  size_t pdu_size,
  Cvcoctci2023Radio *radio_idx)
{
  Log(kTCIA3LogLevel_Event, "Processing received TCI16093DSRC message - req_type: %d\n", parse_params->u.request.req_type);

  int ret = kTCIA3ResponseMsgType_Response;
  switch (parse_params->u.request.req_type)
  {
    case kCvcoctci2023RequestType_SetInitialState:
      ret = TCIA2023_Process16093DSRCSetInitialState(parse_params->u.request.u.set_initial_state);
      break;

    case kCvcoctci2023RequestType_SetWsmTxInfo:
      ret = TCIA2023_Process16093DSRCSetWsmTxInfo(&(parse_params->u.request.u.set_wsm_tx_info));
      break;

    case kCvcoctci2023RequestType_StartWsmTx:
      ret = TCIA2023_Process16093DSRCStartWsmTx(&(parse_params->u.request.u.start_wsm_tx), pdu, pdu_size);
      break;

    case kCvcoctci2023RequestType_StopWsmTx:
      ret = TCIA2023_Process16093DSRCStopWsmTx(&(parse_params->u.request.u.stop_wsm_tx));
      break;

    case kCvcoctci2023RequestType_StartWsmRx:
      ret = TCIA2023_Process16093DSRCStartWsmRx(&(parse_params->u.request.u.start_wsm_rx));
      break;

    case kCvcoctci2023RequestType_StopWsmRx:
      ret = TCIA2023_Process16093DSRCStopWsmRx(&(parse_params->u.request.u.stop_wsm_rx));
      break;

    case kCvcoctci2023RequestType_StartWsaTxPeriodic:
      ret = TCIA2023_Process16093DSRCStartWsaTxPeriodic(&(parse_params->u.request.u.start_wsa_tx_periodic));
      break;

    case kCvcoctci2023RequestType_StopWsaTxPeriodic:
      ret = TCIA2023_Process16093DSRCStopWsaTxPeriodic(&(parse_params->u.request.u.stop_wsa_tx_periodic));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add AddWsaProviderService
     * */
      // NOTE:: 현 버전(2021.03.10 기준)의 TCI 시험에서 본 request 메시지는 사용되지 않고 있다.
    case kCvcoctci2023RequestType_AddWsaProviderService:
      ret = TCIA2023_Process16093DSRCAddWsaProviderService(&(parse_params->u.request.u.add_psr));
      break;

    case kCvcoctci2023RequestType_ChangeWsaProviderService:
      ret = TCIA2023_Process16093DSRCChangeWsaProviderService(&(parse_params->u.request.u.change_psr));
      break;

    case kCvcoctci2023RequestType_DelWsaProviderService:
      ret = TCIA2023_Process16093DSRCDelWsaProviderService(&(parse_params->u.request.u.del_psr));
      break;

    case kCvcoctci2023RequestType_AddUserService:
      ret = TCIA2023_Process16093DSRCAddUserService(&(parse_params->u.request.u.add_usr));
      break;

    case kCvcoctci2023RequestType_DelUserService:
      ret = TCIA2023_Process16093DSRCDelUserService(&(parse_params->u.request.u.del_usr));
      break;

    case kCvcoctci2023RequestType_GetIPv6InterfaceInfo:
      ret = TCIA2023_Process16093DSRCGetIPv6InterfaceInfo(&(parse_params->u.request.u.get_ipv6_info), radio_idx);
      break;

    case kCvcoctci2023RequestType_SetIPv6Address:
      ret = TCIA2023_Process16093DSRCSetIPv6Address(&(parse_params->u.request.u.set_ipv6_addr));
      break;

    case kCvcoctci2023RequestType_StartIPv6Ping:
      ret = TCIA2023_Process16093DSRCStartIPv6Ping(&(parse_params->u.request.u.start_ipv6_ping));
      break;

    case kCvcoctci2023RequestType_StopIPv6Ping:
      ret = TCIA2023_Process16093DSRCStopIPv6Ping(&(parse_params->u.request.u.stop_ipv6_ping));
      break;

    default:
      Err("Fail to process TCI16093DSRC message - invalid request type %d\n", parse_params->u.request.req_type);
      ret = -1;
      break;
  }

  return ret;
}

