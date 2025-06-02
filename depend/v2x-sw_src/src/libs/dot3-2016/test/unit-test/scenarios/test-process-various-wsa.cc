/** 
 * @file
 * @brief 다양한 형태의 WSA 수신에 대한 단위테스트 구현 파일
 * @date 2020-08-01
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief 동일한 Channel Info를 사용하는 Service Info들이 포함된 WSA에 대한 수신 기능 테스트
 */
TEST(PROCESS_VARIOUS_WSA, SERV_INFOS_SHARING_CHAN_INFO)
{
  extern uint8_t g_wsa_with_serv_infos_sharing_chan_info[];
  extern size_t g_wsa_with_serv_infos_sharing_chan_info_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * WSA에 포함된 Service Info들에 대한 USR을 등록한다.
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
  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_wsa_with_serv_infos_sharing_chan_info,
                        g_wsa_with_serv_infos_sharing_chan_info_size,
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
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
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
  ASSERT_EQ(params.wsis[2].channel_index, 1UL);
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
   * UAS 정보를 확인하여 4개의 UAS가 생성된 것을 확인한다.
   *  - 1~3번째 UAS는 동일한 Channel Info를 사용한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 4UL);
  uas = set->uas;
  // 첫번째 UAS 정보 확인
  ASSERT_TRUE(CompareBytes(uas->src_mac_addr, src_mac_addr, MAC_ALEN));
  ASSERT_EQ(uas->wsa_type, wsa_type);
  ASSERT_EQ(uas->rcpi, rcpi);
  ASSERT_EQ(uas->tx_lat, tx_lat);
  ASSERT_EQ(uas->tx_lon, tx_lon);
  ASSERT_EQ(uas->tx_elev, tx_elev);
  ASSERT_TRUE(uas->available);
  ASSERT_EQ(uas->wsa_id, 1UL);
  ASSERT_EQ(uas->psid, 0UL);
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
  //두번째 UAS 정보 확인
  uas = set->uas + 1;
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
  //세번째 UAS 정보 확인
  uas = set->uas + 2;
  ASSERT_TRUE(CompareBytes(uas->src_mac_addr, src_mac_addr, MAC_ALEN));
  ASSERT_EQ(uas->wsa_type, wsa_type);
  ASSERT_EQ(uas->rcpi, rcpi);
  ASSERT_EQ(uas->tx_lat, tx_lat);
  ASSERT_EQ(uas->tx_lon, tx_lon);
  ASSERT_EQ(uas->tx_elev, tx_elev);
  ASSERT_TRUE(uas->available);
  ASSERT_EQ(uas->wsa_id, 1UL);
  ASSERT_EQ(uas->psid, 2UL);
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
  // 세번째 UAS 정보 확인
  uas = set->uas + 3;
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
  ASSERT_FALSE(uas->present.wra);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Service Info는 포함하지 않고 Channel Info만 포함하는 WSA에 대한 수신 처리 기능 테스트
 *  - 해당 WSA는 잘못된 WSA는 아니지만, UAS가 생성되지 않으므로 서비스 측면에서는 의미를 갖지 못하는 WSA이다.
 */
TEST(PROCESS_VARIOUS_WSA, NO_SERV_INFO)
{
  InitTestEnv();

  extern uint8_t g_wsa_with_no_serv_info[];
  extern size_t g_wsa_with_no_serv_info_size;

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * Service Info들에 대한 USR을 등록한다.
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
  ret = Dot3_ProcessWSA(g_wsa_with_no_serv_info,
                        g_wsa_with_no_serv_info_size,
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
  ASSERT_EQ(params.wsi_num, 0UL);
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
   * UAS 정보를 확인하여 UAS가 생성되지 않은 것을 확인한다.
   *  - WSA 내에 Service Info 정보가 존재하지 않으므로 UAS도 생성되지 않는다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief USR에 등록된 Advertiser ID와 다른 Advertiser ID를 갖는 WSA 헤더 수신 시 UAS가 생성되지 않는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA, DIFFERENT_ADVERTISER_ID)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;

  /*
   * 샘플 WSA에 대응되는 USR을 등록한다.
   *  - 샘플 WSA 헤더의 Advertiser ID와 다른 Advertiser ID를 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  usr.present.advertiser_id = true;
  usr.advertiser_id.len = strlen("1");
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
  ret = Dot3_ProcessWSA(g_min_wsa_with_some_ext,
                        g_min_wsa_with_some_ext_size,
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
  ASSERT_TRUE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.hdr.advertiser_id.len, strlen("0"));
  ASSERT_TRUE(CompareString(params.hdr.advertiser_id.id, "0"));
  // Service Info 파싱 정보 확인 - 내용 확인은 생략
  ASSERT_EQ(params.wsi_num, 1UL);
  // Channel Info 파싱 정보 확인 - 내용 확인은 생략
  ASSERT_EQ(params.wci_num, 1UL);
  // WRA 파싱 정보 확인 - 내용 확인은 생략
  ASSERT_TRUE(params.present.wra);

  /*
   * UAS 정보를 확인하여 UAS가 생성되지 않은 것을 확인한다.
   *  - 등록된 USR과 WSA 헤더의 Advertiser ID가 다르므로 UAS가 생성되지 않는다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief USR에 등록된 PSC와 다른 PSC를 갖는 Service Info 수신 시 UAS가 생성되지 않는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA, DIFFERENT_PSC)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;

  /*
   * Service Info에 대응되는 USR들을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  // 1번째 Service Info에 대응되는 USR - PSC의 마지막 글자를 다르게 등록한다.
  usr.psid = 15;
  usr.wsa_type = kDot3WSAType_Unsecured;
  usr.present.psc = true;
  usr.psc.len = strlen("0123456789012345678901234567891");
  memcpy(usr.psc.psc, "0123456789012345678901234567891", usr.psc.len);
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);
  // 2번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 31;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 2);
  // 3번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 47;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 3);
  // 4번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 63;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 4);
  // 5번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 79;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 5);
  // 6번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 95;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 6);
  // 7번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 111;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 7);
  // 8번째 Service Info에 대응되는 USR
  memset(&usr, 0, sizeof(usr));
  usr.psid = 127;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 8);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
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
  // Service Info 파싱 정보 확인 - PSC 정보를 확인한다.
  ASSERT_EQ(params.wsi_num, 8UL);
  ASSERT_TRUE(params.wsis[0].extensions.psc);
  ASSERT_EQ(params.wsis[0].psc.len, strlen("0123456789012345678901234567890"));
  ASSERT_TRUE(CompareString(params.wsis[0].psc.psc, "0123456789012345678901234567890"));
  // Channel Info 파싱 정보 확인 - 내용 확인은 생략
  ASSERT_EQ(params.wci_num, 8UL);
  // WRA 파싱 정보 확인 - 내용 확인은 생략
  ASSERT_TRUE(params.present.wra);

  /*
   * UAS 정보를 확인하여 7개의 UAS가 생성된 것을 확인한다.
   *  - 8개의 Service Info 중에 PSC가 맞지 않는 첫번째 Service Info를 제외한 나머지 Service Info들에 대한 UAS가 생성된다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 7UL);
  ASSERT_EQ((set->uas + 0)->psid, 31UL);
  ASSERT_EQ((set->uas + 1)->psid, 47UL);
  ASSERT_EQ((set->uas + 2)->psid, 63UL);
  ASSERT_EQ((set->uas + 3)->psid, 79UL);
  ASSERT_EQ((set->uas + 4)->psid, 95UL);
  ASSERT_EQ((set->uas + 5)->psid, 111UL);
  ASSERT_EQ((set->uas + 6)->psid, 127UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 시스템이 지원하는 수(kDot3WSINum_Max, 현재 31)보다 많은 Service Info를 포함한 WSA 수신 시
 *        지원되는 개수까지만 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA, TOO_MANY_SERVICE_INFO)
{
  extern uint8_t g_wsa_with_too_many_service_info[];
  extern size_t g_wsa_with_too_many_service_info_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * WSA에 포함된 Service Info들에 대한 USR을 등록한다.
   * 테스트벡터와 동일한 PSID 및 개수만큼 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.wsa_type = kDot3WSAType_Unsecured;
  for (unsigned int i = 0; i < kDot3WSINum_Max + 1; i++) {
    usr.psid = i + 1;
    ASSERT_EQ(Dot3_AddUSR(&usr), (int)(i+1));
  }

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_wsa_with_too_many_service_info,
                        g_wsa_with_too_many_service_info_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 파싱된 ServiceInfo의 개수가 시스템이 지원하는 최대 개수수(=kDot3WSINum_Max)인 것을 확인한다.
   */
  ASSERT_EQ(params.wsi_num, kDot3WSINum_Max);

  /*
   * 시스템이 지원하는 최대 개수(=kDot3WSINum_Max)까지만 UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, kDot3WSINum_Max);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief 시스템이 지원하는 수(kDot3WCINum_Max, 현재 31)보다 많은 Channel Info를 포함한 WSA 수신 시
 *        지원되는 개수까지만 처리하는 것을 확인한다.
 */
TEST(PROCESS_VARIOUS_WSA, TOO_MANY_CHANNEL_INFO)
{
  extern uint8_t g_wsa_with_too_many_channel_info[];
  extern size_t g_wsa_with_too_many_channel_info_size;

  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  /*
   * WSA에 포함된 Service Info에 대한 USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.wsa_type = kDot3WSAType_Unsecured;
  usr.psid = 1;
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
  ret = Dot3_ProcessWSA(g_wsa_with_too_many_channel_info,
                        g_wsa_with_too_many_channel_info_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 파싱된 ServiceInfo의 개수가 시스템이 지원하는 최대 개수(=kDot3WCINum_Max)인 것을 확인한다.
   */
  ASSERT_EQ(params.wci_num, kDot3WCINum_Max);

  /*
   * 한개의 UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  free(set);

  ReleaseTestEnv();
}

