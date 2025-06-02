/** 
 * @file
 * @brief
 * @date 2021-03-08
 * @author gyun
 */


#ifndef V2X_SW_TCIA2023_TYPES_H
#define V2X_SW_TCIA2023_TYPES_H


/**
 * @brief 디버그 메시지 출력 레벨
 */
enum eTCIA3LogLevel
{
  kTCIA3LogLevel_None = 0,
  kTCIA3LogLevel_Err = 1,
  kTCIA3LogLevel_Init = 2,
  kTCIA3LogLevel_Event = 3,
  kTCIA3LogLevel_DetailedEvent = 4,
  kTCIA3LogLevel_PktDump = 5,
  kTCIA3LogLevel_All,
};
typedef unsigned int TCIALogLevel; ///< @ref eTCIA3LogLevel


/**
 * @brief TS로 전송할 Response 메시지의 유형
 */
enum eTCIA3ResponseMsgType
{
  kTCIA3ResponseMsgType_Response, ///< Response 메시지 응답
  kTCIA3ResponseMsgType_ResponseInterfaceInfo, ///< IPv6 Interface 정보가 담긴 ResponseInfo 메시지 응답
  kTCIA3ResponseMsgType_ResponseSutInfo, ///< SuT 정보가 담긴 ResponseInfo 메시지 응답.
  kTCIA3ResponseMsgType_ResponseAtCmdInfo, ///< AT command가 담긴 ResponseInfo 메시지 응답.
  kTCIA3ResponseMsgType_ResponsePacketCount, ///< Packet count가 담긴 ResponseInfo 메시지 응답.
  kTCIA3ResponseMsgType_ResponseSutStatus, ///< SUT status가 담긴 ResponseInfo 메시지 응답.
  kTCIA3ResponseMsgType_ResponseSent, ///< Response 메시지가 전송되었음. (Restart에서 사용)
};
typedef unsigned int TCIA3ResponseMsgType; ///< @ref eTCIA3ResponseType


/**
 * @brief 테스트 중인 프로토콜 유형
 * TS로부터 수신한 Request 메시지의 프레임 유형에 의해 설정된다.
 */
enum eTCIA3TestProtocol
{
  kTCIA3TestProtocol_16093dsrc,
  kTCIA3TestProtocol_16093pc5,
  kTCIA3TestProtocol_80211,
  kTCIA3TestProtocol_16094,
  kTCIA3TestProtocol_29451,
  kTCIA3TestProtocol_31611,
  kTCIA3TestProtocol_NA = -999,
};
typedef int TCIA3TestProtocol; ///< @ref eTCIA3TestProtocol


/**
 * @brief IPv6 주소 유형
 */
enum eTCIA3IPv6AddressType
{
  kTCIA3IPv6AddressTyp_global = 0x0000,
  kTCIA3IPv6AddressTyp_loopback = 0x0010,
  kTCIA3IPv6AddressTyp_link_local = 0x0020,
  kTCIA3IPv6AddressTyp_site_local = 0x0040,
};
typedef uint16_t TCIA3IPv6AddressType; ///< @ref  eTCIA3IPv6AddressType


#endif //V2X_SW_TCIA2023_TYPES_H
