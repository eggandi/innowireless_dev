/** 
 * @file
 * @brief 다양한 형태의 잘못된 WSA 수신에 대한 단위테스트 구현 파일
 * @date 2020-08-01
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


extern uint8_t g_abnormal_wsa_with_no_chan_info[];
extern size_t g_abnormal_wsa_with_no_chan_info_size;

/**
 * @brief Channel Info가 존재하지 않는 WSA에 대한 수신 기능 테스트
 *  - 해당 WSA는 잘못된 WSA로써 라이브러리는 이에 대해 예외처리를 성공적으로 수행해야 한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, NO_CHAN_INFO)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * g_abnormal_wsa_with_no_chan_info에 포함된 Service Info들에 대한 USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  // 첫번째 USR 등록
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);
  // 두번째 USR 등록
  usr.psid = 1;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 2);
  // 세번째 USR 등록
  usr.psid = 2;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 3);
  // 네번째 USR 등록
  usr.psid = 3;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 4);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_no_chan_info,
                        g_abnormal_wsa_with_no_chan_info_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  ASSERT_EQ(ret, kDot3Result_Success);
  // 헤더 파싱 정보 확인
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, 1UL);
  ASSERT_EQ(params.hdr.content_count, 0UL);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  // Service Info 파싱 정보 확인
  ASSERT_EQ(params.wsi_num, 4UL);
  ASSERT_EQ(params.wsis[0].psid, 0UL);
  ASSERT_EQ(params.wsis[0].channel_index, 0UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wsis[1].psid, 1UL);
  ASSERT_EQ(params.wsis[1].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[1].extensions.psc);
  ASSERT_FALSE(params.wsis[1].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[1].extensions.service_port);
  ASSERT_FALSE(params.wsis[1].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[1].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[1].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[1].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wsis[2].psid, 2UL);
  ASSERT_EQ(params.wsis[2].channel_index, 3UL);
  ASSERT_FALSE(params.wsis[2].extensions.psc);
  ASSERT_FALSE(params.wsis[2].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[2].extensions.service_port);
  ASSERT_FALSE(params.wsis[2].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[2].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[2].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[2].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wsis[3].psid, 3UL);
  ASSERT_EQ(params.wsis[3].channel_index, 2UL);
  ASSERT_FALSE(params.wsis[3].extensions.psc);
  ASSERT_FALSE(params.wsis[3].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[3].extensions.service_port);
  ASSERT_FALSE(params.wsis[3].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[3].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[3].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[3].extensions.wsa_cnt_threshold_interval);
  // Channel Info 파싱 정보 확인
  ASSERT_EQ(params.wci_num, 0UL);
  // WRA 파싱 정보 확인
  ASSERT_FALSE(params.present.wra);

  /*
   * UAS 정보를 확인하여 UAS가 생성되지 않은 것을 확인한다.
   *  - 모든 Service Info가 참조할 수 있는 Channel Info가 존재하지 않으므로 UAS가 생성되지 않아야 한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


extern uint8_t g_abnormal_wsa_with_serv_info_with_invalid_chan_idx[];
extern size_t g_abnormal_wsa_with_serv_info_with_invalid_chan_idx_size;

/**
 * @brief 잘못된 Channel Index 값을 갖는 Service Info를 포함하는 WSA에 대한 수신 기능 테스트
 *  - 해당 WSA는 잘못된 WSA로써 라이브러리는 이에 대해 예외처리를 성공적으로 수행해야 한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, SERV_INFO_WITH_INVALID_CHAN_IDX)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * g_abnormal_wsa_with_serv_info_with_invalid_chan_idx에 포함된 Service Info들에 대한 USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  // 첫번째 USR 등록
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);
  // 두번째 USR 등록
  usr.psid = 1;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 2);
  // 세번째 USR 등록
  usr.psid = 2;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 3);
  // 네번째 USR 등록
  usr.psid = 3;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 4);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_serv_info_with_invalid_chan_idx,
                        g_abnormal_wsa_with_serv_info_with_invalid_chan_idx_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  ASSERT_EQ(ret, kDot3Result_Success);
  // 헤더 파싱 정보 확인
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, 1UL);
  ASSERT_EQ(params.hdr.content_count, 0UL);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  // Service Info 파싱 정보 확인
  ASSERT_EQ(params.wsi_num, 4UL);
  ASSERT_EQ(params.wsis[0].psid, 0UL);
  ASSERT_EQ(params.wsis[0].channel_index, 0UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wsis[1].psid, 1UL);
  ASSERT_EQ(params.wsis[1].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[1].extensions.psc);
  ASSERT_FALSE(params.wsis[1].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[1].extensions.service_port);
  ASSERT_FALSE(params.wsis[1].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[1].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[1].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[1].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wsis[2].psid, 2UL);
  ASSERT_EQ(params.wsis[2].channel_index, 3UL);
  ASSERT_FALSE(params.wsis[2].extensions.psc);
  ASSERT_FALSE(params.wsis[2].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[2].extensions.service_port);
  ASSERT_FALSE(params.wsis[2].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[2].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[2].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[2].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wsis[3].psid, 3UL);
  ASSERT_EQ(params.wsis[3].channel_index, 2UL);
  ASSERT_FALSE(params.wsis[3].extensions.psc);
  ASSERT_FALSE(params.wsis[3].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[3].extensions.service_port);
  ASSERT_FALSE(params.wsis[3].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[3].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[3].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[3].extensions.wsa_cnt_threshold_interval);
  // Channel Info 파싱 정보 확인
  ASSERT_EQ(params.wci_num, 2UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, -128);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_EQ(params.wcis[1].operating_class, 18UL);
  ASSERT_EQ(params.wcis[1].chan_num, 175UL);
  ASSERT_EQ(params.wcis[1].transmit_power_level, -127);
  ASSERT_EQ(params.wcis[1].datarate, kDot3DataRate_12Mbps);
  ASSERT_EQ(params.wcis[1].adaptable_datarate, true);
  ASSERT_FALSE(params.wcis[1].extension.chan_access);
  ASSERT_FALSE(params.wcis[1].extension.edca_param_set);
  // WRA 파싱 정보 확인
  ASSERT_FALSE(params.present.wra);

  /*
   * UAS 정보를 확인하여 UAS가 2개만 생성된 것을 확인한다.
   *  - Channel Index가 유효한 2번째, 4번째 Service Info에 대한 UAS만이 생성되어야 한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 2UL);
  uas = set->uas;
  // 2번째 Service Info로부터 생성된 1번째 UAS 정보 확인
  ASSERT_TRUE(CompareBytes(uas->src_mac_addr, src_mac_addr, MAC_ALEN));
  ASSERT_EQ(uas->wsa_type, wsa_type);
  ASSERT_EQ(uas->rcpi, rcpi);
  ASSERT_EQ(uas->tx_lat, tx_lat);
  ASSERT_EQ(uas->tx_lon, tx_lon);
  ASSERT_EQ(uas->tx_elev, tx_elev);
  ASSERT_TRUE(uas->available);
  ASSERT_EQ(uas->wsa_id, 1UL);
  ASSERT_EQ(uas->psid, 1UL);
  ASSERT_EQ(uas->operating_class, 17UL);
  ASSERT_EQ(uas->chan_num, 172UL);
  ASSERT_EQ(uas->transmit_power_level, -128);
  ASSERT_EQ(uas->datarate, kDot3DataRate_3Mbps);
  ASSERT_FALSE(uas->adaptable_datarate);
  ASSERT_FALSE(uas->present.advertiser_id);
  ASSERT_FALSE(uas->present.psc);
  ASSERT_FALSE(uas->present.ipv6_address);
  ASSERT_FALSE(uas->present.service_port);
  ASSERT_FALSE(uas->present.provider_mac_address);
  ASSERT_FALSE(uas->present.rcpi_threshold);
  ASSERT_FALSE(uas->present.wsa_cnt_threshold);
  ASSERT_FALSE(uas->present.wsa_cnt_threshold_interval);
  ASSERT_FALSE(uas->present.edca_param_set);
  ASSERT_FALSE(uas->present.chan_access);
  ASSERT_FALSE(uas->present.wra);
  // 4번째 Service Info로부터 생성된 2번째 UAS 정보 확인
  uas = set->uas + 1;
  ASSERT_TRUE(CompareBytes(uas->src_mac_addr, src_mac_addr, MAC_ALEN));
  ASSERT_EQ(uas->wsa_type, wsa_type);
  ASSERT_EQ(uas->rcpi, rcpi);
  ASSERT_EQ(uas->tx_lat, tx_lat);
  ASSERT_EQ(uas->tx_lon, tx_lon);
  ASSERT_EQ(uas->tx_elev, tx_elev);
  ASSERT_TRUE(uas->available);
  ASSERT_EQ(uas->wsa_id, 1UL);
  ASSERT_EQ(uas->psid, 3UL);
  ASSERT_EQ(uas->operating_class, 18UL);
  ASSERT_EQ(uas->chan_num, 175UL);
  ASSERT_EQ(uas->transmit_power_level, -127);
  ASSERT_EQ(uas->datarate, kDot3DataRate_12Mbps);
  ASSERT_TRUE(uas->adaptable_datarate);
  ASSERT_FALSE(uas->present.advertiser_id);
  ASSERT_FALSE(uas->present.psc);
  ASSERT_FALSE(uas->present.ipv6_address);
  ASSERT_FALSE(uas->present.service_port);
  ASSERT_FALSE(uas->present.provider_mac_address);
  ASSERT_FALSE(uas->present.rcpi_threshold);
  ASSERT_FALSE(uas->present.wsa_cnt_threshold);
  ASSERT_FALSE(uas->present.wsa_cnt_threshold_interval);
  ASSERT_FALSE(uas->present.edca_param_set);
  ASSERT_FALSE(uas->present.chan_access);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 잘못된 messageID 값을 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_MSG_ID)
{
  extern uint8_t g_abnormal_wsa_with_invalid_msg_id[];
  extern size_t g_abnormal_wsa_with_invalid_msg_id_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_msg_id,
                        g_abnormal_wsa_with_invalid_msg_id_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSAMessage);

  ReleaseTestEnv();
}


/**
 * @brief 잘못된 version 값을 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_VERSION)
{
  extern uint8_t g_abnormal_wsa_with_invalid_version[];
  extern size_t g_abnormal_wsa_with_invalid_version_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_version,
                        g_abnormal_wsa_with_invalid_version_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSAVersion);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 PISD 값을 갖는 Service Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_PSID)
{
  extern uint8_t g_abnormal_wsa_with_invalid_psid[];
  extern size_t g_abnormal_wsa_with_invalid_psid_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_psid,
                        g_abnormal_wsa_with_invalid_psid_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   *  - UAS가 생성되려면 USR을 등록해야 하는데... 유효하지 않은 PSID값이라 USR을 등록할 수가 없다..... 로그로 확인!!
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 RCPI threshold 값을 갖는 Service Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_RCPI_THRESHOLD)
{
  extern uint8_t g_abnormal_wsa_with_invalid_rcpi_threshold[];
  extern size_t g_abnormal_wsa_with_invalid_rcpi_threshold_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_rcpi_threshold,
                        g_abnormal_wsa_with_invalid_rcpi_threshold_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 WSA count threshold 값을 갖는 Service Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_WSA_COUNT_THRESHOLD)
{
  extern uint8_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold[];
  extern size_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_wsa_cnt_threshold,
                        g_abnormal_wsa_with_invalid_wsa_cnt_threshold_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 WSA count threshold interval 값을 갖는 Service Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_WSA_COUNT_THRESHOLD_INTERVAL)
{
  extern uint8_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval[];
  extern size_t g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval,
                        g_abnormal_wsa_with_invalid_wsa_cnt_threshold_interval_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


#if 0 // NOTE:: 국내에서는 Operating class로 어떤 값을 사용할지 정의되어 있지 않으므로, 유효성 검사를 생략한다.
/**
 * @brief 유효하지 않은 operating class 값을 갖는 Channel Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_OPERATING_CLASS)
{
  extern uint8_t g_abnormal_wsa_with_invalid_op_class[];
  extern size_t g_abnormal_wsa_with_invalid_op_class_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_op_class,
                        g_abnormal_wsa_with_invalid_op_class_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}
#endif


/**
 * @brief 유효하지 않은 Channel number 값을 갖는 Channel Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_CHAN_NUM)
{
  extern uint8_t g_abnormal_wsa_with_invalid_chan[];
  extern size_t g_abnormal_wsa_with_invalid_chan_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_chan,
                        g_abnormal_wsa_with_invalid_chan_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 datarate 값을 갖는 Channel Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_DATARATE)
{
  extern uint8_t g_abnormal_wsa_with_invalid_datarate[];
  extern size_t g_abnormal_wsa_with_invalid_datarate_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_datarate,
                        g_abnormal_wsa_with_invalid_datarate_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 Channel access 값을 갖는 Channel Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_CHAN_ACCESS)
{
  extern uint8_t g_abnormal_wsa_with_invalid_chan_access[];
  extern size_t g_abnormal_wsa_with_invalid_chan_access_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_chan_access,
                        g_abnormal_wsa_with_invalid_chan_access_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되지 않은 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 Router lifetime 값을 갖는 WRA를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_ROUTER_LIFETIME)
{
  extern uint8_t g_abnormal_wsa_with_invalid_router_lifetime[];
  extern size_t g_abnormal_wsa_with_invalid_router_lifetime_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_router_lifetime,
                        g_abnormal_wsa_with_invalid_router_lifetime_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS는 생성되었으나 WRA 정보는 없는 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  ASSERT_EQ((set->uas)->psid, 0UL);
  ASSERT_FALSE((set->uas)->present.wra);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 유효하지 않은 IPv6 prefix len 값을 갖는 WRA를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_IP_PREFIX_LEN)
{
  extern uint8_t g_abnormal_wsa_with_invalid_ip_prefix_len[];
  extern size_t g_abnormal_wsa_with_invalid_ip_prefix_len_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_invalid_ip_prefix_len,
                        g_abnormal_wsa_with_invalid_ip_prefix_len_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS는 생성되었으나 WRA 정보는 없는 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  ASSERT_EQ((set->uas)->psid, 0UL);
  ASSERT_FALSE((set->uas)->present.wra);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 너무 긴 PSC 값을 갖는 Service Info를 포함한 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "psc OCTET STRING (SIZE(0..31))" -> 길이의 범위가 고정되어 있으므로, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_PSC)
{
}


/**
 * @brief 너무 짧거나 긴 AdvertiserId 값을 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "AdvertiserIdentifier ::= UTF8String (SIZE (1..32))" -> 길이의 범위가 고정되어 있으므로, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, INVALID_ADVERTISERID)
{
}


/**
 * @brief 포함되면 안되는 확장필드(예: ServiceInfo 등에 포함되는 확장필드)를 포함한 헤더를 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "SrvAdvMsgHeaderExtTypes EXT-TYPE ::= {" 구문으로 들어갈 수 있는 확장필드가 제한되어 있어, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, NOT_SUPPORTED_HEADER_EXTENSION)
{
}


/**
 * @brief 포함되면 안되는 확장필드(예: ChannelInfo 등에 포함되는 확장필드)를 포함한 ServiceInfo를 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "ServiceInfoExtTypes EXT-TYPE ::= {" 구문으로 들어갈 수 있는 확장필드가 제한되어 있어, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, NOT_SUPPORTED_SERVICE_INFO_EXTENSION)
{
}


/**
 * @brief 포함되면 안되는 확장필드(예: ServiceInfo 등에 포함되는 확장필드)를 포함한 ChannelInfo를 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "ChannelInfoExtTypes EXT-TYPE ::= {" 구문으로 들어갈 수 있는 확장필드가 제한되어 있어, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, NOT_SUPPORTED_CHANNEL_INFO_EXTENSION)
{
}


/**
 * @brief 포함되면 안되는 확장필드(예: ServiceInfo 등에 포함되는 확장필드)를 포함한 WRA를 갖는 WSA 수신 시 정상적으로 예외 처리하는 것을 확인한다.
 *
 * asn.1 에 "RoutAdvertExtTypes EXT-TYPE ::= {" 구문으로 들어갈 수 있는 확장필드가 제한되어 있어, asn.1 원문 자체를 바꾸지 않는 이상
 * 테스트벡터를 생성할 수 없다.
 * 따라서 본 테스트는 수행하지 않는다.
 */
TEST(PROCESS_VARIOUS_WSA_ABNORMAL, NOT_SUPPORTED_WRA_EXTENSION)
{
}
