/**
 * @file
 * @brief tcia3 어플리케이션 메인 헤더 파일
 * @date 2019-09-23
 * @author gyun
 */

#ifndef V2X_SW_TCIA2023_H
#define V2X_SW_TCIA2023_H


// 시스템 헤더 파일
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>

// 라이브러리 헤더 파일
#include "cvcoctci-2023/cvcoctci2023.h"
#if defined(_LTEV2X_HAL_)
#include "dot3-2016/dot3.h"
#else
#include "dot3/dot3.h"
#endif
#include "wlanaccess/wlanaccess.h"
#include "j29451/j29451.h"

// 1609.2 라이브러리 헤더 파일
#if defined(_LTEV2X_HAL_)
#include "dot2-2016/dot2.h"
#else
#include "dot2/dot2.h"
#endif

// 어플리케이션 헤더 파일
#include "tcia2023-defines.h"
#include "tcia2023-types.h"
#include "tcia2023-funcs.h"


#if 0
/**
 * @brief J29451 필수정보 구조체
 * */
struct TCIA3J29451TxInfo
{
  bool enable_user_gnss_data;
  
  J29451Acceleration acc_lon;
  J29451Acceleration acc_lat;
  J29451VerticalAcceleration acc_vert;
  J29451YawRate acc_yaw;
  
  J29451VehicleWidth vehicle_width;
  J29451VehicleLength vehicle_length;

  J29451Latitude lat;
  J29451Longitude lon;
  J29451Elevation elev;

  J29451SemiMajorAxisAccuracy semi_major;
  J29451SemiMinorAxisAccuracy semi_minor;
  J29451SemiMajorAxisOrientation semi_orien;

  J29451Speed speed;
  J29451Heading heading;
};
#endif

/**
 * @brief WSA, WSM 서명 관련 정보
 */
struct TCIA3WSASecurityInfo
{
  Cvcoctci2023ContentType content_type; ///< 컨텐츠 유형 - 서명 WSA 송신 시: Ieee16092Data, 비서명 WSA 송신 시: Wsa
  Cvcoctci2023SignerIdentifierType signer_id_type; ///< WSA 서명 시, 서명자 식별자 유형
};

/**
 * @brief WSM 송수신 정보
 *
 * TS로부터 수신된 SetWsmTxInfo 와 StartWsmTx 메시지에 의해 설정되며, WSM 전송 시에 사용된다.
 */
struct TCIA3WSMTrxInfo
{
  unsigned int if_idx; ///< WSM 패킷을 송신할 인터페이스 번호
  bool chan_num_ext; ///< 채널번호 확장필드 포함 여부
  bool datarate_ext; ///< 데이터레이트 확장필드 포함 여부
  bool txpower_ext; ///< 송신파워 확장필드 포함 여부
  Dot3PSID psid; ///< 송신할 WSM PSID
  Dot3ChannelNumber chan_num; ///< WSM 패킷을 송신할 채널번호
  Dot3TimeSlot timeslot; ///< WSM 패킷을 송신할 시간슬롯
  Dot3DataRate datarate; ///< WSM 패킷을 송신할 데이터레이트
  Dot3Power tx_power; ///< WSM 패킷을 송신할 파워
  Dot3Priority priority; ///< WSM 패킷을 송신할 우선순위
  unsigned int packet_count; ///< WSM 패킷을 전송할 캐수
  unsigned int repeat_rate; ///< WSM 패킷을 송신할 빈도 (5초당 송신 횟수)
  uint8_t dst_mac_addr[MAC_ALEN]; ///< WSM 패킷의 목적지 주소
  size_t pdu_size; ///< 송신할 WSM 패킷의 WSM body의 크기
  uint8_t pdu[kWalMPDUSize_MaxWithoutCRC]; ///< 송신할 WSM 패킷의 WSM body
  volatile bool txing; ///< 현재 송신 중인지 여부를 나타내는 플래그 변수
  volatile bool j29451_bsm_txing; ///< 현재 J29451 BSM 메시지를 송신 중인지 여부를 나타내는 플래그 변수
  struct Cvcoctci2023EventHandling event_handling; ///< 수신 메시지에 대한 처리 방법을 명시한 이벤트 핸들링
  
  size_t pdu_filter_size;
  uint8_t pdu_filter[PDU_FILTER_MAX_LEN+1];
  size_t ssp_size;
  uint8_t ssp[SSP_MAX_LEN+1];
  Cvcoctci2023FlowIdentifier flow_id;
  Cvcoctci2023FlowType flow_type;

  struct TCIA3WSASecurityInfo sec_info;

  // 주기적인 송신을 위해 사용되는 타이머
  struct {
    pthread_mutex_t mtx;
    pthread_cond_t cond;
    pthread_t thread;
    timer_t timer;
    unsigned int cnt;
  } tx_timer;
};


/**
 * @brief WSA 전송 관련 정보
 */
struct TCIA3WSATxInfo
{
  unsigned int if_idx; ///< WSA를 송신할 인터페이스 번호
  Dot3ChannelNumber chan_num; ///< WSA 송신 채널 번호
  Dot3TimeSlot timeslot; ///< WSA를 송신할 시간슬롯
  Dot3DataRate datarate; ///< WSA 송신 데이터레이터
  Dot3Power tx_power; ///< WSA 송신 파워
  Dot3Priority priority; ///< WSA 송신 우선순위
  unsigned int repeat_rate; ///< WSA 송신 주기 (5초당 회수)
  uint8_t dst_mac_addr[MAC_ALEN]; ///< WSA 목적지 MAC 주소
  volatile bool txing; ///< 현재 송신 중인지 여부를 나타내는 플래그 변수
  timer_t tx_timer; ///< 주기적인 송신을 위해 사용되는 타이머
  Cvcoctci2023FlowIdentifier flow_id;
};


/**
 * @brief WSA 헤더 정보
 *
 * WSA 헤더에 수납되는 정보를 포함한다.
 */
struct TCIA3WSAHdrInfo
{
  /// WSA 확장 헤더 수납 여부
  struct {
    bool repeat_rate;
    bool twod_location;
    bool threed_location;
    bool advertiser_id;
  } options;

  uint8_t content_count;
  struct Dot3WSAAdvertiserID advertiser_id; ///< WSA 확장헤더에 수납될 advertiser_id
  Dot3Latitude latitude; ///< WSA 확장헤더에 수납될 2DLocation.latitude 또는 3DLocation.latitude
  Dot3Longitude longitude; ///< WSA 확장헤더에 수납될 2DLocation.longitude 또는 3DLocation.longitude
  Dot3Elevation elevation; ///< WSA 확장헤더에 수납될 3DLocation.latitude
  Dot3WSARepeatRate repeat_rate; ///< WSA 확장헤더에 수납될 repeat_rate
};


/**
 * @brief WRA 정보
 */
struct TCIA3WRAInfo
{
  // WRA 확장 필드 수납여부
  struct {
    bool wra;
    bool secondary_dns;
    bool gw_mac_addr;
  } options;

  Cvcoctci2023RouterLifetime router_lifetime;
  uint8_t ip_prefix[IPv6_ALEN];
  Cvcoctci2023IPv6PrefixLength ip_prefix_len;
  uint8_t default_gw[IPv6_ALEN];
  uint8_t primary_dns[IPv6_ALEN];
  uint8_t secondary_dns[IPv6_ALEN];
  uint8_t gw_mac_addr[MAC_ALEN];
};


/**
 * @brief WSA 정보
 */
struct TCIA3WSAInfo
{
  struct TCIA3WSATxInfo tx_info; ///< 송신정보
  struct TCIA3WSAHdrInfo hdr_info; ///< 헤더정보
  struct TCIA3WSASecurityInfo sec_info; ///< 보안정보
  struct TCIA3WRAInfo wra_info; ///< WRA 정보
  uint8_t wsa[kWalMPDUSize_MaxWithoutCRC]; ///< 생성된 WSA 데이터
  size_t wsa_size; ///< 생성된 WSA 데이터의 길이
};


/**
 * @brief TS(Test System)과의 인터페이스에 관련된 정보
 */
struct TCIA3TestSystemInterfaceInfo
{
  uint16_t port; ///< TS로부터 TCI 메시지를 수신하는 포트번호
  int sock; ///< TS와의 TCI 인터페이스 소켓
  pthread_t thread; ///< TCI 메시지 수신 쓰레드
  bool thread_running; ///< TCI 메시지 수신 쓰레드 동작 여부
  struct sockaddr_in my_addr; ///< DUT 소켓주소
  struct sockaddr_in ts_addr; ///< TS 소켓 주소
};


/**
 * @brief IP 네트워킹 관련 정보
 */
struct TCIA3IPNetworkingInfo
{
  /// IP 서비스 동작 중인지 여부.
  /// 수신 WSA에 의한 채널접속/IP할당이 이미 수행되었는지 확인하여 중복 설정하는 것을 방지하기 위해 사용된다.
  bool ip_service_running;

  bool gw_mac_addr_configured; ///< Gateway MAC 주소 설정 여부
  uint8_t gw_mac_addr[MAC_ALEN]; ///< Gateway MAC 주소
};

#if defined(_LTEV2X_HAL_)
struct TCIA3FlowInfo {
  LTEV2XHALTxFlowType type;
  LTEV2XHALTxFlowIndex index;
  LTEV2XHALPriority pppp;
  LTEV2XHALPower power;
  LTEV2XHALTxFlowInterval interval;
  LTEV2XHALMSDUSize size;
};
#endif

/**
 * @brief 프로그램 관리정보
 */
struct TCIA2023_MIB
{
  struct TCIA3IPNetworkingInfo ip_net_info; ///< IP 네트워킹 정보
  struct TCIA3TestSystemInterfaceInfo ts_if_info; ///< TS(Test System) 인터페이스 정보
  struct TCIA3WSMTrxInfo wsm_trx_info[3]; /// 시간슬롯별 WSM 송수신정보
                                         /// 0: TimeSlot0(Alternating), 1: TimeSlot1(Alternating), 2: Continuous
  struct TCIA3WSAInfo wsa_info; ///< WSA 정보
#if 0
  struct TCIA3J29451TxInfo j29451_tx_info; ///< J29451 정보
#endif
#if defined(_LTEV2X_HAL_)
  struct TCIA3FlowInfo flow_info[3];
#endif

  /// V2X 인터페이스 관련 정보
  struct {
    unsigned int if_num; ///< DUT가 지원하는 V2X 인터페이스 개수
    uint8_t mac_addr[V2X_IF_MAX_NUM][MAC_ALEN]; ///< 각 V2X 인터페이스 MAC 주소
    int rcpi_correction[V2X_IF_MAX_NUM]; ///< 각 V2X 인터페이스 RCPI 보정 정보 (deprecated)
  } v2x_if;

  /// Security 관련 정보
  struct {
    char cmhf_dir[MAXLINE+1]; ///< CMHF 저장디렉토리 (문자열)
    char rca_cert_file[MAXLINE+1]; /// RCA 인증서 저장디렉토리 (문자열)
    char ica_cert_file[MAXLINE+1]; /// RCA 인증서 저장디렉토리 (문자열)
    char pca_cert_file[MAXLINE+1]; /// RCA 인증서 저장디렉토리 (문자열)
  } security;

  /// 차량 크기정보
  struct {
    J29451VehicleLength len;
    J29451VehicleWidth width;
  } vehicle_size;

  /// 어플리케이션 실행 입력 파라미터
  struct {
    char dev_name[MAXLINE+1];
    uint16_t tci_port;
    char mac_addr[V2X_IF_MAX_NUM][MAXLINE+1];
    int rcpi_correction[V2X_IF_MAX_NUM];
    int32_t lat;
    int32_t lon;
    uint16_t elev;
    bool auto_bsm_tx;
    bool bsm_replay;
    char cmhf_dir[MAXLINE+1];
    char rca_cert_file[MAXLINE+1]; /// RCA 인증서 저장디렉토리 (문자열)
    char ica_cert_file[MAXLINE+1]; /// RCA 인증서 저장디렉토리 (문자열)
    char pca_cert_file[MAXLINE+1]; /// RCA 인증서 저장디렉토리 (문자열)
  } input_params;

  /// 테스트 관련 정보
  struct {
    volatile bool testing; ///< 현재 테스트 진행 중인지 여부를 나타내는 플래그
    TCIA3TestProtocol test_protocol; ///< 현재 테스트 중인 프로토콜
    bool auto_bsm_tx; ///< BSM을 자동으로 전송할지 여부(set될 경우, tcia 프로그램 실행 시 자동으로 BSM 전송이 시작된다)
    struct {
      uint32_t tx_wsm[3]; ///< 시간슬롯별 WSM 송신 개수 - 0: TimeSlot0(Alternating), 1: TimeSlot1(Alternating), 2: Continuous
      uint32_t rx_wsm[3]; ///< 시간슬롯별 WSM 수신 개수 - 0: TimeSlot0(Alternating), 1: TimeSlot1(Alternating), 2: Continuous
      uint32_t tx_wsa; ///< WSA 송신 개수
    } pkt_cnt; ///< 테스트 진행 중 송수신된 패킷 개수
  } testing;

  /// 로그 메시지 출력 레벨
  struct {
    TCIALogLevel tcia; ///< tcia 어플리케이션 로그 메시지 출력 레벨
    /// V2X 라이브러리 로그 메시지 출력 레벨
    struct {
      unsigned int cvcoctci3;
      unsigned int dot2;
      unsigned int dot3;
      unsigned int j29451;
      unsigned int lteaccess;
      unsigned int wlanaccess;
    } lib;
  } log;

  /// User GNSS Data 정보
  /// TS에 의해 User GNSS data 정보가 설정될 때마다 업데이트되며, Restart 후 j29451 라이브러리에 초기값으로 설정된다.
  struct {
    bool use; // User GNSS Data 사용 여부 (TS의 EnableGpsInput 명령에 의해 설정된다)
    J29451Latitude lat; ///< 위도
    J29451Longitude lon; ///< 경도
    J29451Elevation elev; ///< 고도
    J29451Speed speed; ///< 속도
    J29451Heading heading; ///< 헤딩 (true north)
    struct {
      J29451SemiMajorAxisAccuracy semi_major; ///< semi-major axis accuracy
      J29451SemiMinorAxisAccuracy semi_minor; ///< semi-minor axis accuracy
      J29451SemiMajorAxisOrientation orientation; ///< semi-major asix orientation
    } pos_accuracy; ///< 좌표 정확성
    struct {
      J29451Acceleration lon; ///< 종방향 가속도
      J29451Acceleration lat; ///< 횡방향 가속도
      J29451VerticalAcceleration vert; // 수직방향 가속도
      J29451YawRate yaw; ///< yaw rate
    } acceleration_set; ///< 가속도 정보
  } user_gnss_data;
};


/*
 * 프로그램 내에서 사용되는 전역 변수 및 함수
 */
extern struct TCIA2023_MIB g_tcia_mib;

#endif //V2X_SW_TCIA2023_H
