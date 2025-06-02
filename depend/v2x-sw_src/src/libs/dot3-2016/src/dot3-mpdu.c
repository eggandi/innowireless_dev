/**
 * @file
 * @brief MPDU 생성/파싱 기능 구현 파일
 * @date 2019-08-03
 * @author gyun
 */

// 시스템 헤더 파일
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/// WSMP EtherType
#define ETHERTYPE_WSMP 0x88DC

/*
 * Frame Control 필드 설정/확인 매크로
 */
#define DOT11_GET_FC_PVER(fc) (fc & 3)
#define DOT11_GET_FC_FTYPE(fc) ((fc >> 2) & 3)
#define DOT11_GET_FC_FSTYPE(fc) ((fc >> 4) & 0xf)
#define DOT11_GET_FC_TODS(fc) ((fc >> 8) & 1)
#define DOT11_GET_FC_FROMDS(fc) ((fc >> 9) & 1)
#define DOT11_GET_FC_MOREFRAG(fc) ((fc >> 10) & 1)
#define DOT11_GET_FC_RETRY(fc) ((fc >> 11) & 1)
#define DOT11_GET_FC_PWRMGT(fc) ((fc >> 12) & 1)
#define DOT11_GET_FC_MOREDATA(fc) ((fc >> 13) & 1)
#define DOT11_GET_FC_ISWEP(fc) ((fc >> 14) & 1)
#define DOT11_GET_FC_ORDER(fc) ((fc >> 15) & 1)
#define DOT11_SET_FC_PVER(n) (uint16_t)(n & 3)
#define DOT11_SET_FC_FTYPE(n) (uint16_t)((n & 3) << 2)
#define DOT11_SET_FC_FSTYPE(n) (uint16_t)((n & 0xf) << 4)
#define DOT11_SET_FC_TODS(n) (uint16_t)((n & 1) << 8)
#define DOT11_SET_FC_FROMDS(n) (uint16_t)((n & 1) << 9)
#define DOT11_SET_FC_MOREFRAG(n) (uint16_t)((n & 1) << 10)
#define DOT11_SET_FC_RETRY(n) (uint16_t)((n & 1) << 11)
#define DOT11_SET_FC_PWRMGT(n) (uint16_t)((n & 1) << 12)
#define DOT11_SET_FC_MOREDATA(n) (uint16_t)((n & 1) << 13)
#define DOT11_SET_FC_ISWEP(n) (uint16_t)((n & 1) << 14)
#define DOT11_SET_FC_ORDER(n) (uint16_t)((n & 1) << 15)

/*
 * Sequence Control 필드 설정/확인 매크로
 */
#define	DOT11_GET_SC_SEQ(sc) ((sc >> 4) & 0xfff)
#define	DOT11_GET_SC_FRAG(sc) (sc & 0xf)
#define DOT11_SET_SC_SEQ(n) (uint16_t)((n & 0xfff) << 4)
#define DOT11_SET_SC_FRAG(n) (uint16_t)(n & 0xf)

/*
 * QoS Control 필드 설정/확인 매크로
 */
#define	DOT11_GET_QC_TID(qc) (qc & 0xf)
#define	DOT11_GET_QC_EOSP(qc) ((qc >> 4) & 1)
#define	DOT11_GET_QC_ACK_POLICY(qc) ((qc >> 5) & 3)
#define	DOT11_GET_QC_AMSDU_PRESENT(qc)	((qc >> 7) & 1)
#define	DOT11_GET_QC_TXOP_DUR_REQ(qc) ((qc >> 8) & 0xff)
#define	DOT11_GET_QC_UP(qc) DOT11_GET_QC_TID(qc)
#define	DOT11_SET_QC_TID(n) (uint16_t)(n & 0xf)
#define	DOT11_SET_QC_EOSP(n) (uint16_t)((n & 1) << 4)
#define	DOT11_SET_QC_ACK_POLICY(n) (uint16_t)((n & 3) << 5)
#define	DOT11_SET_QC_AMSDU_PRESENT(n) (uint16_t)((n & 1) << 7)
#define	DOT11_SET_QC_TXOP_DUR_REQ(n) (uint16_t)((n & 0xff) << 8)
#define	DOT11_SET_QC_UP(n) DOT11_SET_QC_TID(n)

/*
 * 개별/그룹 MAC주소 확인 매크로
 */
#define DOT11_GET_MAC_ADDR_IG(addr) (addr[0]&1)
#define DOT11_MAC_ADDR_IG_INDIVIDUAL 0
#define DOT11_MAC_ADDR_IG_GROUP 1


/**
 * @brief 802.11 Frame control type
 */
enum eDot11FcType
{
  kDot11FcType_mgmt = 0,
  kDot11FcType_ctrl = 1,
  kDot11FcType_data = 2,
};
typedef uint16_t Dot11FcType; ///< @ref eDot11FcType


/**
 * @brief 802.11 Frame control subtype
 */
enum eDot11FcSubType
{
  kDot11FcSubType_data = 0x0,
  kDot11FcSubType_ta = 0x6,
  kDot11FcSubType_qos_data = 0x8,
  kDot11FcSubType_rts = 0xb,
  kDot11FcSubType_cts = 0xc,
  kDot11FcSubType_ack = 0xd
};
typedef uint16_t Dot11FcSubType; ///< @ref eDot11FcSubType


/**
 * @brief 802.11 Service class
 *
 * 멀티캐스트인 경우 NoAck, 유니캐스트인 경우 Ack으로 설정된다.
 */
enum eDot11ServiceClass
{
  kDot11ServiceClass_QosAck,
  kDot11ServiceClass_QosNoAck,
};
typedef uint16_t Dot11ServiceClass; ///< @ref eDot11ServiceClass

/// wildcard BSSID (all 1)
static const uint8_t wildcard_bssid[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/// 802.11 프로토콜 버전
static const uint8_t kDot11ProtocolHdr_ProtocolVersion = 0;


/**
 * @brief MPDU를 생성한다.
 * @param[in] params MAC 헤더구성정보
 * @param[in] msdu MSDU가 담긴 버퍼
 * @param[in] msdu_size MSDU의 길이
 * @param[out] mpdu_size 생성된 MPDU의 길이가 반환될 변수의 포인터
 * @param[out] err 실패 시 에러코드(-Dot3ResultCode)가 반환될 변수의 포인터
 * @retval 생성된 MPDU: 성공
 * @retval NULL: 실패
 */
uint8_t INTERNAL *
dot3_ConstructMPDU(struct Dot3MACProcessParams *params, uint8_t *msdu, size_t msdu_size, size_t *mpdu_size, int *err)
{
  Log(kDot3LogLevel_Event, "Construct MPDU - msdu_size: %u\n", msdu_size);

  /*
   * MPDU 버퍼를 할당한다.
   */
  uint8_t *mpdu = calloc(1, sizeof(struct Dot11MACHdr) + sizeof(struct LLCHdr) + msdu_size);
  if (mpdu == NULL) {
    *err = -kDot3Result_NoMemory;
    return NULL;
  }

  /*
   * MAC 헤더를 수납한다.
   */
  struct Dot11MACHdr *mac_hdr = (struct Dot11MACHdr *)mpdu;
  mac_hdr->fc = DOT11_SET_FC_FTYPE(kDot11FcType_data) | DOT11_SET_FC_FSTYPE(kDot11FcSubType_qos_data);
  mac_hdr->dur = 0;
  memcpy(mac_hdr->addr1, params->dst_mac_addr, MAC_ALEN);
  memcpy(mac_hdr->addr2, params->src_mac_addr, MAC_ALEN);
  memset(mac_hdr->addr3, 0xff, MAC_ALEN);
  mac_hdr->sc = 0xFFFE; // for LLC library(SAF5400)
  mac_hdr->qc = DOT11_SET_QC_UP(params->priority);
  if (DOT11_GET_MAC_ADDR_IG(params->dst_mac_addr) == DOT11_MAC_ADDR_IG_INDIVIDUAL) {
    mac_hdr->qc |= DOT11_SET_QC_ACK_POLICY(kDot11ServiceClass_QosAck);
  } else {
    mac_hdr->qc |= DOT11_SET_QC_ACK_POLICY(kDot11ServiceClass_QosNoAck);
  }

  /*
   * LLC 헤더를 수납한다.
   */
  struct LLCHdr *llc_hdr = (struct LLCHdr *)(mpdu + sizeof(struct Dot11MACHdr));
  llc_hdr->type = htons(ETHERTYPE_WSMP);

  /*
   * MSDU를 수납한다.
   */
  memcpy(mpdu + sizeof(struct Dot11MACHdr) + sizeof(struct LLCHdr), msdu, msdu_size);

  *mpdu_size = sizeof(struct Dot11MACHdr) + sizeof(struct LLCHdr) + msdu_size;

  Log(kDot3LogLevel_Event, "Success to construct %u-bytes MPDU\n", *mpdu_size);
  return mpdu;
}


/**
 * @brief MPDU를 파싱한다.
 * @param[in] mpdu 파싱할 MPDU가 저장된 버퍼의 주소를 전달한다.
 * @param[out] params 수신파라미터정보가 저장될 정보구조체의 주소를 전달한다.
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 *
 * MPDU 의 MAC 헤더와 LLC 헤더를 파싱하면서 각 필드의 유효성도 확인한다. 유효하지 않을 경우 실패를 반환한다.
 */
int INTERNAL dot3_ParseMPDU(const uint8_t *mpdu, struct Dot3MACProcessParams *params)
{
  Log(kDot3LogLevel_Event, "Parse MPDU\n");

  /*
   * MAC 헤더 파싱
   *  - 각 필드 유효성 확인 및 반환정보 저장
   *  - NOTE:: 필드 유효성 확인을 이미 하위계층에서 수행했을 경우(예: 칩 드라이버), 생략할 수 있다.
   */
  const struct Dot11MACHdr *mac_hdr = (const struct Dot11MACHdr *)mpdu;
  uint16_t fc = mac_hdr->fc;
  uint8_t ver = DOT11_GET_FC_PVER(fc);
  if (ver != kDot11ProtocolHdr_ProtocolVersion) {
    Err("Fail to parse MPDU - invalid 802.11 protocol version %u\n", ver);
    return -kDot3Result_InvalidLowerLayerProtocolVersion;
  }
  uint8_t ftype = DOT11_GET_FC_FTYPE(fc);
  uint8_t fstype = DOT11_GET_FC_FSTYPE(fc);
  if (ftype != kDot11FcType_data) {
    Err("Fail to parse MPDU - invalid ftype %u\n", ftype);
    return -kDot3Result_InvalidLowerLayerFrameType;
  }
  if (fstype != kDot11FcSubType_qos_data) {
    Err("Fail to parse MPDU - invalid fstype %u\n", fstype);
    return -kDot3Result_InvalidLowerLayerFrameType;
  }
  memcpy(params->dst_mac_addr, mac_hdr->addr1, MAC_ALEN);
  memcpy(params->src_mac_addr, mac_hdr->addr2, MAC_ALEN);
  if (memcmp(mac_hdr->addr3, wildcard_bssid, MAC_ALEN) != 0) {
    Err("Fail to parse MPDU - addr3 is not wildcard bssid. it's %02X:%02X:%02X:%02X:%02X:%02X\n",
        mac_hdr->addr3[0], mac_hdr->addr3[1], mac_hdr->addr3[2],
        mac_hdr->addr3[3], mac_hdr->addr3[4], mac_hdr->addr3[5]);
    return -kDot3Result_NotWildcardBSSID;
  }
  params->priority = DOT11_GET_QC_UP(mac_hdr->qc);

  /*
   * LLC 헤더 파싱
   */
  const struct LLCHdr *llc_hdr = (const struct LLCHdr *)(mpdu + sizeof(struct Dot11MACHdr));
  uint16_t ether_type = ntohs(llc_hdr->type);
  if (ether_type != ETHERTYPE_WSMP) {
    Err("Fail to parse MDPU - not supported ether type 0x%04X\n", ether_type);
    return -kDot3Result_NotSupportedEtherType;
  }

  Log(kDot3LogLevel_Event, "Success to parse MPDU\n");
  return kDot3Result_Success;
}
