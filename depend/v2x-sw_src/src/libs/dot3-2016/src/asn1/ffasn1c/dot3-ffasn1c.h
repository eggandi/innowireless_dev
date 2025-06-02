/**
 * @file
 * @brief ffasn1c 라이브러리 기반 인코딩/디코딩 관련 기능 정의 파일
 * @date 2019-08-02
 * @author gyun
 */


#ifndef V2X_LIBDOT3_DOT3_ASN1_FFASN1C_H
#define V2X_LIBDOT3_DOT3_ASN1_FFASN1C_H


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot3-2016.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


extern const int kShortMsgVersionNo;


/**
 * @brief 확장필드 식별자
 */
enum eDot3ExtensionID
{
  // for WSMP-N-Header
  kDot3ExtensionID_TxPowerUsed80211 = 4,
  kDot3ExtensionID_ChannelNumber80211 = 15,
  kDot3ExtensionID_DataRate80211 = 16,

  // for WSA header
  kDot3ExtensionID_RepeatRate = 17,
  kDot3ExtensionID_2DLocation = 5,
  kDot3ExtensionID_3DLocation = 6,
  kDot3ExtensionID_AdvertiserID = 7,

  // for WSA service info
  kDot3ExtensionID_PSC = 8,
  kDot3ExtensionID_IPv6Address = 9,
  kDot3ExtensionID_ServicePort = 10,
  kDot3ExtensionID_ProviderMACAddress = 11,
  kDot3ExtensionID_RCPIThreshold = 19,
  kDot3ExtensionID_WSACountThreshold = 20,
  kDot3ExtensionID_WSACountThresholdInterval = 22,

  // for WSA channel info
  kDot3ExtensionID_EDCAParameterSet = 12,
  kDot3ExtensionID_ChannelAccess = 21,

  // for WRA
  kDot3ExtensionID_SecondaryDNS = 13,
  kDot3ExtensionID_GatewayMACAddress = 14
};
typedef int Dot3ExtensionID;  ///< @ref eDot3ExtensionID


/*
 * 함수 원형(들)
 */
int INTERNAL dot3_ffasn1c_FillVarLengthNumber(Dot3PSID psid, dot3VarLengthNumber *var_len_num);
int INTERNAL dot3_ffasn1c_ParseVarLengthNumber(const dot3VarLengthNumber *var_len_num);
int INTERNAL dot3_ffasn1c_DecodeWSA(const uint8_t *wsa, size_t wsa_size, struct Dot3ParseWSAParams *params);
uint8_t INTERNAL * dot3_ffasn1c_EncodeWSA(const struct Dot3ConstructWSAParams *params, size_t *wsa_size, int *err);
uint8_t INTERNAL * dot3_ffasn1c_EncodeWSM(
  struct Dot3WSMConstructParams *params,
  const uint8_t *payload,
  Dot3WSMPayloadSize payload_size,
  size_t *wsm_size,
  int *err);
uint8_t INTERNAL * dot3_ffasn1c_DecodeWSM(
  const uint8_t *wsm,
  Dot3WSMSize wsm_size,
  size_t *payload_size,
  struct Dot3WSMParseParams *params,
  int *ret);

#endif //V2X_LIBDOT3_DOT3_ASN1_FFASN1C_H
