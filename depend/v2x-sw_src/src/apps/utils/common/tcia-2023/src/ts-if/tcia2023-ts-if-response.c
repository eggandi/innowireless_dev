/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


// 시스템 헤더 파일
#include <stdio.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief TCI Response 메시지를 생성하여 전송한다.
 * @param[in] frame_type Response 메시지 유형
 * @param[in] msg_id Request 메시지의 식별자 (Response 메시지에 수납된다)
 * @param[in] result Request 메시지 처리 결과 (Response 메시지에 수납된다)
 */
void TCIA2023_ConstructAndSendTCIResponse(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result)
{
  struct Cvcoctci2023Response resp_params = CVCOCTCI2023_RESPONSE_CONSTRUCT_PARAMS_INITIALIZER;
  resp_params.msg_id = msg_id;
  resp_params.result_code = (result == 0) ? kCvcoctci2023TciResultCode_Success : kCvcoctci2023TciResultCode_Failure;

  uint8_t txbuf[TCI_MSG_MAX_SIZE];

  /*
   * 프레임 유형 별 Response 메시지를 생성한다.
   */
  int pkt_size;
  switch (frame_type) {
    
    /**
     * Update TCIv3 by young@KETI
     * 16093 rename to 16093dsrc
     * */
    // TCI 16093 DSRC Response
    case kCvcoctci2023FrameType_16093Dsrc:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093DSRC Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093DsrcResponse(&resp_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add 16093pc5
     * */
    // TCI 16093 PC5 Response
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16093PC5 Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093Pc5Response(&resp_params, txbuf, sizeof(txbuf));
      break;

    // TCI 80211 Response
    case kCvcoctci2023FrameType_80211:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI80211 Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_Construct80211Response(&resp_params, txbuf, sizeof(txbuf));
      break;

    // TCI 16094 Response
    case kCvcoctci2023FrameType_16094:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI16094 Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_Construct16094Response(&resp_params, txbuf, sizeof(txbuf));
      break;

    // TCI 29451 Response
    case kCvcoctci2023FrameType_29451:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI29451 Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_Construct29451Response(&resp_params, txbuf, sizeof(txbuf));
      break;
    
    /**
     * Update TCIv3 by young@KETI
     * Add 31611
     * */
    // TCI 31611 Response
    case kCvcoctci2023FrameType_31611:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCI31611 Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_Construct31611Response(&resp_params, txbuf, sizeof(txbuf));
      break;

    // TCI SutControl Response
    case kCvcoctci2023FrameType_SutControl:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCISutControl Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_ConstructSutControlResponse(&resp_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add proxyCv2x
     * */
    // TCI proxy cv2x Response
    case kCvcoctci2023FrameType_ProxyCv2x:
      Log(kTCIA3LogLevel_DetailedEvent, "Construct TCIPROXYCV2X Response message - msg_id: %u, result_code: %d\n",
          resp_params.msg_id, resp_params.result_code);
      pkt_size = Cvcoctci2023_ConstructProxyCv2xResponse(&resp_params, txbuf, sizeof(txbuf));
      break;

    default:
      Err("Fail to construct TCI response - invalid frame type %d\n", frame_type);
      return;
  }

  if (pkt_size < 0) {
    Err("Fail to construct TCI response - ret: %d\n", pkt_size);
    return;
  }
  Log(kTCIA3LogLevel_DetailedEvent, "Success to construct %d bytes TCI response\n", pkt_size);

  /*
   * 패킷을 전송한다.
   */
  TCIA2023_SendTCIMessagePacket(txbuf, pkt_size);
}


/**
 * @brief 특정 인터페이스에 대한 주소 정보 등이 수납된 TCI ResponseInfo 메시지를 생성하여 전송한다.
 * @param[in] frame_type ResponseInfo 메시지 유형
 * @param[in] msg_id Request 메시지의 식별자 (Response 메시지에 수납된다)
 * @param[in] result Request 메시지 처리 결과 (Response 메시지에 수납된다)
 * @param[in] radio_idx 요청된 인터페이스 식별번호 (Response 메시지에 수납된다)
 */
void TCIA2023_ConstructAndSendTCIResponseInterfaceInfo(
  Cvcoctci2023TciFrameType frame_type,
  uint8_t msg_id,
  int result,
  Cvcoctci2023Radio radio_idx)
{
  struct Cvcoctci2023ResponseInfo resp_info_params;
  memset(&resp_info_params, 0, sizeof(resp_info_params));
  resp_info_params.options.info = true;
  resp_info_params.msg_id = msg_id;
  resp_info_params.result_code = (result == 0) ? kCvcoctci2023TciResultCode_Success : kCvcoctci2023TciResultCode_Failure;
  resp_info_params.info_type = kCvcoctci2023InfoContentType_IPv6InterfaceInfo;

  uint8_t txbuf[TCI_MSG_MAX_SIZE];

  /*
   * 인터페이스 정보를 획득한다.
   */
  int ret = TCIA2023_GetInterfaceInfo(radio_idx, &(resp_info_params.info.infos));
  if (ret < 0) {
    return;
  }

  /*
   * 프레임 유형 별 ResponseInfo 메시지를 생성한다.
   */
  int pkt_size;
  switch (frame_type) {
    
    /**
     * Update TCIv3 by young@KETI
     * 16093 rename to 16093dsrc
     * */
    // TCI 16093 ResponseInfo
    case kCvcoctci2023FrameType_16093Dsrc:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093DSRC ResponseInfo(Ipv6InterfaceInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093DsrcResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add 16093pc5
     * */
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093PC5 ResponseInfo(Ipv6InterfaceInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093Pc5ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    // TCI 16094 ResponseInfo
    case kCvcoctci2023FrameType_16094:
      Log(kTCIA3LogLevel_Event, "Construct TCI16094 ResponseInfo(Ipv6InterfaceInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16094ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * 80211 does not support the ResponseInfo message
     * 29451 does not support the ResponseInfo message
     * 31611 does not support the ResponseInfo message
     * sutControl does not support the ipv6InterfaceInfo of ResponseInfo message
     * proxyCv2x does not support the ipv6InterfaceInfo of ResponseInfo message
     * */

    default:
      Err("Fail to construct TCI ResponseInfo - invalid frame type %d\n", frame_type);
      return;
  }

  if (pkt_size < 0) {
    Err("Fail to construct TCI ResponseInfo - ret: %d\n", pkt_size);
    return;
  }
  Log(kTCIA3LogLevel_Event, "Success to construct %d bytes TCI ResponseInfo\n", pkt_size);

  /*
   * 패킷을 전송한다.
   */
  TCIA2023_SendTCIMessagePacket(txbuf, pkt_size);
}


/**
 * @brief SUT 정보가 수납된 TCI ResponseInfo 메시지를 생성하여 전송한다.
 * @param[in] frame_type ResponseInfo 메시지 유형
 * @param[in] msg_id Request 메시지의 식별자 (ResponseInfo 메시지에 수납된다)
 * @param[in] result Request 메시지 처리 결과 (ResponseInfo 메시지에 수납된다)
 */
void TCIA2023_ConstructAndSendTCIResponseSutInfo(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result)
{
  struct Cvcoctci2023ResponseInfo resp_info_params;
  memset(&resp_info_params, 0, sizeof(resp_info_params));
  resp_info_params.options.info = true;
  resp_info_params.msg_id = msg_id;
  resp_info_params.result_code = (result == 0) ? kCvcoctci2023TciResultCode_Success : kCvcoctci2023TciResultCode_Failure;
  resp_info_params.info_type = kCvcoctci2023InfoContentType_SutInfo;

  /*
   * 회신할 SUT 정보를 설정한다
   *  - v2x-sw 버전정보만 하나 수납한다. (나머지 필드들은 모두 옵션)
   */
  resp_info_params.info.sut_info.version_infos.info_cnt = 1;
  resp_info_params.info.sut_info.version_infos.info[0].component_type = kCvcoctci2023ComponentType_Software;
  sprintf(resp_info_params.info.sut_info.version_infos.info[0].version_id, "%s", _VERSION_);

  /*
   * 프레임 유형 별 ResponseInfo 메시지를 생성한다.
   */
  int pkt_size;
  uint8_t txbuf[TCI_MSG_MAX_SIZE];
  switch (frame_type) {
    
    /**
     * Update TCIv3 by young@KETI
     * 16093 renameto 16093dsrc
     * */
    // TCI 16093 DSRC ResponseInfo
    case kCvcoctci2023FrameType_16093Dsrc:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093DSRC ResponseInfo(SutInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093DsrcResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add 16093pc5
     * */
    // TCI 16093 PC5 ResponseInfo
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093PC5 ResponseInfo(SutInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093Pc5ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    // TCI 16094 ResponseInfo
    case kCvcoctci2023FrameType_16094:
      Log(kTCIA3LogLevel_Event, "Construct TCI16094 ResponseInfo(SutInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16094ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    // TCI SutControl ResponseInfo
    case kCvcoctci2023FrameType_SutControl:
      Log(kTCIA3LogLevel_Event, "Construct TCISutControl ResponseInfo(SutInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_ConstructSutControlResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * 80211 does not support the ResponseInfo message
     * 29451 does not support the ResponseInfo message
     * 31611 does not support the ResponseInfo message
     * proxyCv2x does not support the sutInfo of ResponseInfo message
     * */

    default:
      Err("Fail to construct TCI ResponseInfo(SutInfo) - invalid frame type %d\n", frame_type);
      return;
  }

  if (pkt_size < 0) {
    Err("Fail to construct TCI ResponseInfo(SutInfo) - ret: %d\n", pkt_size);
    return;
  }
  Log(kTCIA3LogLevel_Event, "Success to construct %d bytes TCI ResponseInfo(SutInfo)\n", pkt_size);

  /*
   * 패킷을 전송한다.
   */
  TCIA2023_SendTCIMessagePacket(txbuf, pkt_size);
}


/**
 * Update TCIv3 by young@KETI
 * Add atCmdInfo
 * 
 * @brief atCmdInfo 정보가 수납된 TCI ResponseInfo 메시지를 생성하여 전송한다.
 * @param[in] frame_type ResponseInfo 메시지 유형
 * @param[in] msg_id Request 메시지의 식별자 (ResponseInfo 메시지에 수납된다)
 * @param[in] result Request 메시지 처리 결과 (ResponseInfo 메시지에 수납된다)
 * @param[in] at_cmd_size 요청된 AT command 메시지 크기 (ResponseInfo 메시지에 수납된다)
 * @param[in] at_cmd 요청된 AT command 메시지 (ResponseInfo 메시지에 수납된다)
 */
void TCIA2023_ConstructAndSendTCIResponseAtCmdInfo(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result, size_t at_cmd_size, uint8_t *at_cmd)
{
  struct Cvcoctci2023ResponseInfo resp_info_params;
  memset(&resp_info_params, 0, sizeof(resp_info_params));
  resp_info_params.options.info = true;
  resp_info_params.msg_id = msg_id;
  resp_info_params.result_code = (result == 0) ? kCvcoctci2023TciResultCode_Success : kCvcoctci2023TciResultCode_Failure;
  resp_info_params.info_type = kCvcoctci2023InfoContentType_ATcmdInfo;

  /*
   * AT command를 설정한다
   */
  resp_info_params.info.at_cmd_info.len = at_cmd_size;
  memcpy(resp_info_params.info.at_cmd_info.buf, at_cmd, at_cmd_size);

  /*
   * 프레임 유형 별 ResponseInfo 메시지를 생성한다.
   */
  int pkt_size;
  uint8_t txbuf[TCI_MSG_MAX_SIZE];
  switch (frame_type) {
    
    /**
     * Update TCIv3 by young@KETI
     * Add 16093pc5
     * */
    // TCI 16093 PC5 ResponseInfo
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093PC5 ResponseInfo(atCmdInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093Pc5ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add proxyCv2x
     * */
    // TCI PROXY CV2X ResponseInfo
    case kCvcoctci2023FrameType_ProxyCv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCIPROXYCV2X ResponseInfo(atCmdInfo) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_ConstructProxyCv2xResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * 80211 does not support the ResponseInfo message
     * 29451 does not support the ResponseInfo message
     * 31611 does not support the ResponseInfo message
     * 16093dsrc does not support the atCmdInfo of ResponseInfo message
     * 16094 does not support the atCmdInfo of ResponseInfo message
     * sutControl does not support the atCmdInfo of ResponseInfo message
     * */

    default:
      Err("Fail to construct TCI ResponseInfo(atCmdInfo) - invalid frame type %d\n", frame_type);
      return;
  }

  if (pkt_size < 0) {
    Err("Fail to construct TCI ResponseInfo(atCmdInfo) - ret: %d\n", pkt_size);
    return;
  }
  Log(kTCIA3LogLevel_Event, "Success to construct %d bytes TCI ResponseInfo(atCmdInfo)\n", pkt_size);

  /*
   * 패킷을 전송한다.
   */
  TCIA2023_SendTCIMessagePacket(txbuf, pkt_size);
}


/**
 * Update TCIv3 by young@KETI
 * Add packetCount
 * 
 * @brief PacketCount 정보가 수납된 TCI ResponseInfo 메시지를 생성하여 전송한다.
 * @param[in] frame_type ResponseInfo 메시지 유형
 * @param[in] msg_id Request 메시지의 식별자 (ResponseInfo 메시지에 수납된다)
 * @param[in] result Request 메시지 처리 결과 (ResponseInfo 메시지에 수납된다)
 * @param[in] pkt_count 요청된 packet count (ResponseInfo 메시지에 수납된다)
 */
void TCIA2023_ConstructAndSendTCIResponsePacketCount(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result, size_t pkt_count)
{
  struct Cvcoctci2023ResponseInfo resp_info_params;
  memset(&resp_info_params, 0, sizeof(resp_info_params));
  resp_info_params.options.info = true;
  resp_info_params.msg_id = msg_id;
  resp_info_params.result_code = (result == 0) ? kCvcoctci2023TciResultCode_Success : kCvcoctci2023TciResultCode_Failure;
  resp_info_params.info_type = kCvcoctci2023InfoContentType_PacketCount;

  /*
   * pkt_count를 설정한다
   */
  resp_info_params.info.pkt_count = pkt_count;

  /*
   * 프레임 유형 별 ResponseInfo 메시지를 생성한다.
   */
  int pkt_size;
  uint8_t txbuf[TCI_MSG_MAX_SIZE];
  switch (frame_type) {
    
    /**
     * Update TCIv3 by young@KETI
     * Add 16093pc5
     * */
    // TCI 16093 PC5 ResponseInfo
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093PC5 ResponseInfo(pktCount) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093Pc5ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add proxyCv2x
     * */
    // TCI PROXY CV2X ResponseInfo
    case kCvcoctci2023FrameType_ProxyCv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCIPROXYCV2X ResponseInfo(pktCount) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_ConstructProxyCv2xResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * 80211 does not support the ResponseInfo message
     * 29451 does not support the ResponseInfo message
     * 31611 does not support the ResponseInfo message
     * 16093dsrc does not support the pktCount of ResponseInfo message
     * 16094 does not support the pktCount of ResponseInfo message
     * sutControl does not support the pktCount of ResponseInfo message
     * */

    default:
      Err("Fail to construct TCI ResponseInfo(pktCount) - invalid frame type %d\n", frame_type);
      return;
  }

  if (pkt_size < 0) {
    Err("Fail to construct TCI ResponseInfo(pktCount) - ret: %d\n", pkt_size);
    return;
  }
  Log(kTCIA3LogLevel_Event, "Success to construct %d bytes TCI ResponseInfo(pktCount)\n", pkt_size);

  /*
   * 패킷을 전송한다.
   */
  TCIA2023_SendTCIMessagePacket(txbuf, pkt_size);
}


/**
 * Update TCIv3 by young@KETI
 * Add sutStatus
 * 
 * @brief SutStatus 정보가 수납된 TCI ResponseInfo 메시지를 생성하여 전송한다.
 * @param[in] frame_type ResponseInfo 메시지 유형
 * @param[in] msg_id Request 메시지의 식별자 (ResponseInfo 메시지에 수납된다)
 * @param[in] result Request 메시지 처리 결과 (ResponseInfo 메시지에 수납된다)
 */
void TCIA2023_ConstructAndSendTCIResponseSutStatus(Cvcoctci2023TciFrameType frame_type, uint8_t msg_id, int result)
{
  struct Cvcoctci2023ResponseInfo resp_info_params;
  memset(&resp_info_params, 0, sizeof(resp_info_params));
  resp_info_params.options.info = true;
  resp_info_params.msg_id = msg_id;
  resp_info_params.result_code = (result == 0) ? kCvcoctci2023TciResultCode_Success : kCvcoctci2023TciResultCode_Failure;
  resp_info_params.info_type = kCvcoctci2023InfoContentType_SutStatus;

  /*
   * sutStatus를 설정한다
   */
  resp_info_params.info.sut_status.len = 0;
  // memcpy(resp_info_params.info.sut_status.buf, ---, resp_info_params.info.sut_status.len);

  /*
   * 프레임 유형 별 ResponseInfo 메시지를 생성한다.
   */
  int pkt_size;
  uint8_t txbuf[TCI_MSG_MAX_SIZE];
  switch (frame_type) {
    
    /**
     * Update TCIv3 by young@KETI
     * Add 16093pc5
     * */
    // TCI 16093 PC5 ResponseInfo
    case kCvcoctci2023FrameType_16093Cv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCI16093PC5 ResponseInfo(sutStatus) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_Construct16093Pc5ResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * Add proxyCv2x
     * */
    // TCI PROXY CV2X ResponseInfo
    case kCvcoctci2023FrameType_ProxyCv2x:
      Log(kTCIA3LogLevel_Event, "Construct TCIPROXYCV2X ResponseInfo(sutStatus) message - msg_id: %u, result_code: %d\n",
          resp_info_params.msg_id, resp_info_params.result_code);
      pkt_size = Cvcoctci2023_ConstructProxyCv2xResponseInfo(&resp_info_params, txbuf, sizeof(txbuf));
      break;

    /**
     * Update TCIv3 by young@KETI
     * 80211 does not support the ResponseInfo message
     * 29451 does not support the ResponseInfo message
     * 31611 does not support the ResponseInfo message
     * 16093dsrc does not support the sutStatus of ResponseInfo message
     * 16094 does not support the sutStatus of ResponseInfo message
     * sutControl does not support the sutStatus of ResponseInfo message
     * */

    default:
      Err("Fail to construct TCI ResponseInfo(sutStatus) - invalid frame type %d\n", frame_type);
      return;
  }

  if (pkt_size < 0) {
    Err("Fail to construct TCI ResponseInfo(sutStatus) - ret: %d\n", pkt_size);
    return;
  }
  Log(kTCIA3LogLevel_Event, "Success to construct %d bytes TCI ResponseInfo(sutStatus)\n", pkt_size);

  /*
   * 패킷을 전송한다.
   */
  TCIA2023_SendTCIMessagePacket(txbuf, pkt_size);
}