/**
 * @file
 * @brief TS와의 인터페이스 관련 기능을 구현한 파일
 * @date 2019-09-23
 * @author gyun
 */


// 시스템 헤더 파일
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"

// 어플리케이션 헤더 파일
#include "include/tcia2023.h"


/**
 * @brief TCI 메시지 통신용 소켓을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int TCIA2023_InitTCISocket(void)
{
  struct TCIA3TestSystemInterfaceInfo *ts_if_info = &(g_tcia_mib.ts_if_info);
  Log(kTCIA3LogLevel_Init, "Initialize TCI UDP socket on port number %u\n", ts_if_info->port);

  /*
   * UDP 소켓을 생성한다.
   */
  Log(kTCIA3LogLevel_Init, "Create TCI interface socket\n");
  ts_if_info->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (ts_if_info->sock < 0) {
    Err("Fail to create TCI interface socket - fail to socket() - %m\n");
    return -1;
  }
  Log(kTCIA3LogLevel_Init, "Success to create TCI interface socket\n");

  /*
   * 생성한 소켓을 바인드 한다.
   */
  Log(kTCIA3LogLevel_Init, "Bind TCI interface socket\n");
  int addr_len = sizeof(ts_if_info->my_addr);
  ts_if_info->my_addr.sin_family = AF_INET;
  ts_if_info->my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  ts_if_info->my_addr.sin_port = htons(ts_if_info->port);
  int ret = bind(ts_if_info->sock, (struct sockaddr *)&(ts_if_info->my_addr), addr_len);
  if (ret < 0) {
    Err("Fail to bin TCI interface socket - fail to bind() - %m\n");
    close(ts_if_info->sock);
    return -1;
  }
  Log(kTCIA3LogLevel_Init, "Success to bind TCI interface socket\n");
  Log(kTCIA3LogLevel_Init, "Success to initialize TCI socket\n");
  return 0;
}


/**
 * @brief TCI 메시지 수신/처리 쓰레드 함수
 * @param[in] arg 사용되지 않는다.
 * @return NULL. 프로그램 종료시까지 리턴되지 않는다.
 */
static void * TCIA2023_TCIMessageRxThread(void *arg)
{
  (void)arg;
  struct sockaddr_in peer;
  socklen_t addr_len = sizeof(peer);
  uint8_t rxbuf[TCI_MSG_MAX_SIZE];
  uint8_t pdu[MAX_PDU_SIZE];
  struct Cvcoctci2023Params parse_params;
  struct TCIA3TestSystemInterfaceInfo *ts_if_info = &(g_tcia_mib.ts_if_info);

  Log(kTCIA3LogLevel_Init, "TCI message rx thread started\n");
  ts_if_info->thread_running = true;

  while (1) {

    /*
     * TS로부터 TCI 메시지(UDP 패킷)을 수신한다.
     */
    int rx_pkt_size = recvfrom(ts_if_info->sock, rxbuf, sizeof(rxbuf), 0, (struct sockaddr *)&peer, &addr_len);
    if (rx_pkt_size <= 0) {
      printf("\n");
      Err("Fail to receive TCI message - recvfrom() failed: %m\n");
      continue;
    }

    // TS의 IP 주소 및 UDP 포트를 저장한다.
    // 앞으로는 이 주소 및 포트로 Response/ResponseInfo/Indication/Exception 메시지가 전달된다.
    memcpy(&(ts_if_info->ts_addr), &peer, sizeof(struct sockaddr_in));

    Log(kTCIA3LogLevel_DetailedEvent, "%d bytes UDP packet is received from TS\n", rx_pkt_size);
    TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, rxbuf, rx_pkt_size);
    Log(kTCIA3LogLevel_DetailedEvent, "TS address is set - IP: %s, port: %d\n",
        inet_ntoa(ts_if_info->ts_addr.sin_addr), ntohs(ts_if_info->ts_addr.sin_port));

    /*
     * 수신된 TCI 메시지 패킷을 디코딩하고 파싱한다.
     */
    memset(&parse_params, 0, sizeof(parse_params));
    Log(kTCIA3LogLevel_DetailedEvent, "Decode/parse TCI message\n");
    int pdu_size = Cvcoctci2023_DecodeAndParseTciMessage(rxbuf, rx_pkt_size, &parse_params, pdu, sizeof(pdu));
    if (pdu_size < 0) {
      Err("Fail to decode and parse TCI message - %d\n", pdu_size);
      continue;
    }
    Log(kTCIA3LogLevel_DetailedEvent, "Success to decode and parse TCI message\n");

    /*
     * 파싱된 정보에 따라 관련 동작을 수행한다.
     */
    Cvcoctci2023Radio radio_idx;
    int ret = TCIA2023_ProcessTCIMessage(&parse_params, pdu, (size_t)pdu_size, &radio_idx);

    /**
     * Update TCIv3 by young@KETI
     * Add pkt_count parameter
     * */
#if defined(_TCIA2023_DSRC_)
    size_t pkt_count = 0;
#elif defined(_TCIA2023_LTE_V2X_)
    size_t pkt_count = g_tcia_mib.testing.pkt_cnt.rx_wsm[kDot3TimeSlot_Continuous];
#endif
    /*
     * TS 로 Response/ResponseInfo 메시지를 생성하여 전송한다.
     */
    if (ret == kTCIA3ResponseMsgType_Response) {
      TCIA2023_ConstructAndSendTCIResponse(parse_params.frame_type, parse_params.u.request.msg_id, 0);
    } else if (ret == kTCIA3ResponseMsgType_ResponseInterfaceInfo) {
      TCIA2023_ConstructAndSendTCIResponseInterfaceInfo(parse_params.frame_type, parse_params.u.request.msg_id, 0, radio_idx);
    } else if (ret == kTCIA3ResponseMsgType_ResponseSutInfo) {
      TCIA2023_ConstructAndSendTCIResponseSutInfo(parse_params.frame_type, parse_params.u.request.msg_id, 0);
    } else if (ret == kTCIA3ResponseMsgType_ResponseAtCmdInfo) {
      TCIA2023_ConstructAndSendTCIResponseAtCmdInfo(parse_params.frame_type, parse_params.u.request.msg_id, 0, parse_params.u.request.u.send_at_command.len, parse_params.u.request.u.send_at_command.buf);
    } else if (ret == kTCIA3ResponseMsgType_ResponsePacketCount) {
      TCIA2023_ConstructAndSendTCIResponsePacketCount(parse_params.frame_type, parse_params.u.request.msg_id, 0, pkt_count);
    } else if (ret == kTCIA3ResponseMsgType_ResponseSutStatus) {
      TCIA2023_ConstructAndSendTCIResponseSutStatus(parse_params.frame_type, parse_params.u.request.msg_id, 0);
    } else if (ret == kTCIA3ResponseMsgType_ResponseSent) {
      // do nothing.
    } else if (ret < 0) {
      TCIA2023_ConstructAndSendTCIResponse(parse_params.frame_type, parse_params.u.request.msg_id, ret);
    }

    /*
     * 테스트 프로토콜을 설정한다 - 이는 테스트 중 Indication을 생성할 때 사용된다.
     */
    if (ret == 0) {
      TCIA2023_SetTestProtocol(parse_params.frame_type);
    }
  }

  return NULL;
}


/**
 * @brief TS와의 인터페이스 기능을 초기화한다.
 * @param[in] port TCI 메시지가 교환되는 UDP 포트 번호
 * @retval 0: 성공
 * @retval -1: 실패
 */
int TCIA2023_InitTestSystemInterfaceFunction(uint16_t port)
{
  Log(kTCIA3LogLevel_Init, "Initialize TS interface function\n");
  g_tcia_mib.ts_if_info.port = port;

  /*
   * TCI 메시지 교환용 소켓을 초기화한다.
   */
  int ret = TCIA2023_InitTCISocket();
  if (ret < 0) {
    return -1;
  }

  /*
   * TCI 메시지 수신 쓰레드를 생성한다.
   */
  ret = pthread_create(&(g_tcia_mib.ts_if_info.thread), NULL, TCIA2023_TCIMessageRxThread, NULL);
  if (ret) {
    Err("Fail to initialize TS interface function - pthread_create() failed: %m\n");
    return -1;
  }
  while (g_tcia_mib.ts_if_info.thread_running == false) {
    usleep(1000);
  }

  Log(kTCIA3LogLevel_Init, "Success to initialize TS interface function\n");
  return 0;
}


/**
 * @brief TCI 패킷을 UDP로 전송한다.
 * @param[in] pkt 전송할 TCI 패킷
 * @param[in] pkt_size 전송할 TCI 패킷의 크기
 */
void TCIA2023_SendTCIMessagePacket(const uint8_t *pkt, size_t pkt_size)
{
  Log(kTCIA3LogLevel_DetailedEvent, "Send %d bytes TCI message packet\n", pkt_size);
  TCIA2023_PrintPacketDump(kTCIA3LogLevel_PktDump, pkt, pkt_size);

  struct TCIA3TestSystemInterfaceInfo *ts_if_info = &(g_tcia_mib.ts_if_info);
  int ret;
  while(1) {
    ret = sendto(ts_if_info->sock,
                 pkt,
                 pkt_size,
                 0,
                 (struct sockaddr *)&(ts_if_info->ts_addr),
                 sizeof(ts_if_info->ts_addr));
    if (ret == (int)pkt_size) {
      Log(kTCIA3LogLevel_DetailedEvent, "Success to send %u-bytes TCI message packet.\n", pkt_size);
      break;
    } else if (ret < 0){
      Err("Fail to send TCI message packet: %m\n");
    } else {
      Err("Fail to send TCI message packet: partially sent (%d/%u)\n", ret, pkt_size);
    }
  }
}
