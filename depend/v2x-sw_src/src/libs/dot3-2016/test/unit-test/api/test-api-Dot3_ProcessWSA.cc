/** 
 * @file
 * @brief Dot3_ProcessWSA() API에 대한 단위테스트 구현 파일
 * @date 2020-07-29
 * @author gyun
 */


// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief Dot3_ParseWSA() API 호출 시 각 정보가 최소값을 갖고 필수필드만을 포함한 WSA가 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ProcessWSA, MIN_WSA_WITH_NO_EXT)
{
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
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  /*
   * UAS 정보를 확인하여 UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 각 정보가 최소값을 갖고 확장필드를 일부 포함한 WSA가 정상적으로 파싱되는 것을 확인한다.
 */
TEST(Dot3_ProcessWSA, MIN_WSA_WITH_SOME_EXT)
{
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
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Unavailable;
  Dot3Longitude tx_lon = kDot3Longitude_Unavailable;
  Dot3Elevation tx_elev = kDot3Elevation_Unavailable;
  ret = Dot3_ProcessWSA(g_min_wsa_with_some_ext,
                        g_min_wsa_with_some_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_TRUE(params.hdr.extensions.repeat_rate);
  ASSERT_EQ(params.hdr.repeat_rate, kDot3WSARepeatRate_Min);
  ASSERT_TRUE(params.hdr.extensions.twod_location);
  ASSERT_EQ(params.hdr.twod_location.latitude, kDot3Latitude_Min);
  ASSERT_EQ(params.hdr.twod_location.longitude, kDot3Longitude_Min);
  ASSERT_TRUE(params.hdr.extensions.threed_location);
  ASSERT_EQ(params.hdr.threed_location.latitude, kDot3Latitude_Min);
  ASSERT_EQ(params.hdr.threed_location.longitude, kDot3Longitude_Min);
  ASSERT_EQ(params.hdr.threed_location.elevation, kDot3Elevation_Min);
  ASSERT_TRUE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.hdr.advertiser_id.len, strlen("0"));
  ASSERT_TRUE(CompareString(params.hdr.advertiser_id.id, "0"));
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_TRUE(params.present.wra);
  ASSERT_TRUE(CheckWRA(&(params.wra),
                       kDot3WRARouterLifetime_Min,
                       g_my_ipv6_addr,
                       kDot3IPv6PrefixLen_Min,
                       g_my_ipv6_addr,
                       g_my_ipv6_addr,
                       true,
                       g_my_ipv6_addr,
                       true,
                       g_my_addr));

  /*
   * UAS 정보를 확인하여 UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   true, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   true, // wra
                                   params.hdr.threed_location.latitude,
                                   params.hdr.threed_location.longitude,
                                   params.hdr.threed_location.elevation,
                                   &(params.hdr.advertiser_id), // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   &(params.wra))); // wra
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 각 정보가 최대값을 갖고 확장필드를 모두 포함한 WSA가 정상적으로 생성되는 것을 확인한다.
 */
TEST(Dot3_ProcessWSA, MAX_WSA_WITH_ALL_EXT)
{
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
  usr.psid = 15;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);
  usr.psid = 31;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 2);
  usr.psid = 47;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 3);
  usr.psid = 63;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 4);
  usr.psid = 79;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 5);
  usr.psid = 95;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 6);
  usr.psid = 111;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 7);
  usr.psid = 127;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 8);

  /*
   * WSA 파싱정보가 정확한지 확인한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Unavailable;
  Dot3Longitude tx_lon = kDot3Longitude_Unavailable;
  Dot3Elevation tx_elev = kDot3Elevation_Unavailable;
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);;
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Max);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Max);
  ASSERT_TRUE(params.hdr.extensions.repeat_rate);
  ASSERT_EQ(params.hdr.repeat_rate, kDot3WSARepeatRate_Max);
  ASSERT_TRUE(params.hdr.extensions.twod_location);
  ASSERT_EQ(params.hdr.twod_location.latitude, kDot3Latitude_Max);
  ASSERT_EQ(params.hdr.twod_location.longitude, kDot3Longitude_Max);
  ASSERT_TRUE(params.hdr.extensions.threed_location);
  ASSERT_EQ(params.hdr.threed_location.latitude, kDot3Latitude_Max);
  ASSERT_EQ(params.hdr.threed_location.longitude, kDot3Longitude_Max);
  ASSERT_EQ(params.hdr.threed_location.elevation, kDot3Elevation_Max);
  ASSERT_TRUE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.hdr.advertiser_id.len, strlen("01234567890123456789012345678901"));
  ASSERT_TRUE(CompareString(params.hdr.advertiser_id.id, "01234567890123456789012345678901"));
  ASSERT_EQ(params.wsi_num, 8UL);
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[0]), 15, 1));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[1]), 31, 2));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[2]), 47, 3));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[3]), 63, 4));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[4]), 79, 5));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[5]), 95, 6));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[6]), 111, 7));
  ASSERT_TRUE(CheckWSIInMaxWSA(&(params.wsis[7]), 127, 8));
  ASSERT_EQ(params.wci_num, 8UL);
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[0]), 17, 174, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[1]), 18, 177, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[2]), 17, 180, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[3]), 18, 183, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[4]), 18, 173, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[5]), 17, 176, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[6]), 18, 179, kDot3Power_Max, kDot3DataRate_54Mbps, true));
  ASSERT_TRUE(CheckWCIInMaxWSAWithAllExtensions(&(params.wcis[7]), 17, 182, kDot3Power_Max, kDot3DataRate_27Mbps, true));
  ASSERT_TRUE(params.present.wra);
  ASSERT_TRUE(CheckWRA(&(params.wra),
                       kDot3WRARouterLifetime_Max,
                       g_my_ipv6_addr,
                       kDot3IPv6PrefixLen_Max,
                       g_my_ipv6_addr,
                       g_my_ipv6_addr,
                       true,
                       g_my_ipv6_addr,
                       true,
                       g_my_addr));

  /*
   * UAS 정보를 확인하여 UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 8UL);
  for (unsigned int i = 0; i < set->num; i++) {
    uas = set->uas + i;
    ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                      src_mac_addr,
                                      wsa_type,
                                      rcpi,
                                      false, // available
                                      params.hdr.wsa_id,
                                      params.wsis[i].psid,
                                      params.wcis[params.wsis[i].channel_index-1].operating_class,
                                      params.wcis[params.wsis[i].channel_index-1].chan_num,
                                      params.wcis[params.wsis[i].channel_index-1].transmit_power_level,
                                      params.wcis[params.wsis[i].channel_index-1].datarate,
                                      params.wcis[params.wsis[i].channel_index-1].adaptable_datarate));
    ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                     true, // advertiser_id
                                     true, // psc
                                     true, // ipv6 address
                                     true, // service port
                                     true, // provider mac address
                                     true, // rcpi threshold
                                     true, // wsa cnt threshold
                                     true, // wsa cnt threshold interval
                                     true, // edca parameter set
                                     true, // chan access
                                     true, // wra
                                     params.hdr.threed_location.latitude,
                                     params.hdr.threed_location.longitude,
                                     params.hdr.threed_location.elevation,
                                     &(params.hdr.advertiser_id), // advertiser_id
                                     &(params.wsis[i].psc), // psc
                                     params.wsis[i].ipv6_address, // ipv6 address
                                     params.wsis[i].service_port, // service port
                                     params.wsis[i].provider_mac_address, // provider mac address
                                     params.wsis[i].rcpi_threshold, // rcpi threshold
                                     params.wsis[i].wsa_cnt_threshold, // wsa cnt threshold
                                     params.wsis[i].wsa_cnt_threshold_interval, // wsa cnt threshold interval
                                     &(params.wcis[params.wsis[i].channel_index-1].edca_param_set), // edca parameter set
                                     params.wcis[params.wsis[i].channel_index-1].chan_access, // chan access
                                     &(params.wra))); // wra
  }
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 널 파라미터가 전달되는 경우의 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, CHECK_PARAMS_NULL)
{
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
  usr.psid = 15;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);
  usr.psid = 31;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 2);
  usr.psid = 47;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 3);
  usr.psid = 63;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 4);
  usr.psid = 79;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 5);
  usr.psid = 95;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 6);
  usr.psid = 111;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 7);
  usr.psid = 127;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 8);

  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Unavailable;
  Dot3Longitude tx_lon = kDot3Longitude_Unavailable;
  Dot3Elevation tx_elev = kDot3Elevation_Unavailable;

  /*
   * wsa 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(NULL,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * src_mac_addr 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        NULL,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * params 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 전달되는 WSA type 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, CHECK_PARAM_WSA_TYPE)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = wsa_type;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * kDot3WSAType_Unsecured 값을 전달하면 성공하는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        kDot3WSAType_Unsecured,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  /*
   * UAS 정보를 확인하여 UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();
  Dot3_DeleteAllUSRs();

  /*
   * kDot3WSAType_Secured 값을 전달하면 성공하는 것을 확인한다.
   */
  // USR 등록
  wsa_type = kDot3WSAType_Secured;
  memset(&usr, 0, sizeof(usr));
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = wsa_type;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  /*
   * 너무 작은 wsa type 값을 전달하면 성공하는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        kDot3WSAType_Min - 1,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSAType);

  /*
   * 너무 큰 wsa type 값을 전달하면 성공하는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        kDot3WSAType_Max + 1,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidWSAType);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 전달되는 RCPI 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, CHECK_PARAM_RCPI)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = wsa_type;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * 최소 값을 전달하면 성공하는 것을 확인한다.
   */
  rcpi = kDot3RCPI_Min;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 최대 값을 전달하면 성공하는 것을 확인한다.
   */
  rcpi = kDot3RCPI_Max;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  /*
   * 너무 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  rcpi = kDot3RCPI_Max + 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidRCPI);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 전달되는 tx_lat 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, CHECK_PARAM_TX_LAT)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = wsa_type;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * 최소 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_lat = kDot3Latitude_Min;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 최대 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_lat = kDot3Latitude_Max;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * Unavailable 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_lat = kDot3Latitude_Unavailable;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 너무 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  tx_lat = kDot3Latitude_Min - 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidLatitude);

  /*
   * 너무 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  tx_lat = kDot3Latitude_Unavailable + 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidLatitude);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 전달되는 tx_lon 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, CHECK_PARAM_TX_LON)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = wsa_type;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * 최소 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_lon = kDot3Longitude_Min;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 최대 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_lon = kDot3Longitude_Max;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * Unavailable 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_lon = kDot3Longitude_Unavailable;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 너무 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  tx_lon = kDot3Longitude_Min - 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidLongitude);

  /*
   * 너무 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  tx_lon = kDot3Longitude_Unavailable + 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidLongitude);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 전달되는 tx_elev 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, CHECK_PARAM_TX_ELEV)
{
  InitTestEnv();

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params;
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[MAC_ALEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;

  /*
   * USR을 등록한다.
   */
  memset(&usr, 0, sizeof(usr));
  usr.psid = kDot3PSID_Min;
  usr.wsa_type = wsa_type;
  ret = Dot3_AddUSR(&usr);
  ASSERT_EQ(ret, 1);

  /*
   * 최소 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_elev = kDot3Elevation_Min;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 최대 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_elev = kDot3Elevation_Max;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * Unavailable 값을 전달하면 성공하는 것을 확인한다.
   */
  tx_elev = kDot3Elevation_Unavailable;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ASSERT_EQ(params.hdr.version, kDot3WSAVersion_Current);
  ASSERT_EQ(params.hdr.wsa_id, kDot3WSAIdentifier_Min);
  ASSERT_EQ(params.hdr.content_count, kDot3WSAContentCount_Min);
  ASSERT_FALSE(params.hdr.extensions.repeat_rate);
  ASSERT_FALSE(params.hdr.extensions.twod_location);
  ASSERT_FALSE(params.hdr.extensions.threed_location);
  ASSERT_FALSE(params.hdr.extensions.advertiser_id);
  ASSERT_EQ(params.wsi_num, 1UL);
  ASSERT_EQ(params.wsis[0].psid, kDot3PSID_Min);
  ASSERT_EQ(params.wsis[0].channel_index, 1UL);
  ASSERT_FALSE(params.wsis[0].extensions.psc);
  ASSERT_FALSE(params.wsis[0].extensions.ipv6_address);
  ASSERT_FALSE(params.wsis[0].extensions.service_port);
  ASSERT_FALSE(params.wsis[0].extensions.provider_mac_address);
  ASSERT_FALSE(params.wsis[0].extensions.rcpi_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold);
  ASSERT_FALSE(params.wsis[0].extensions.wsa_cnt_threshold_interval);
  ASSERT_EQ(params.wci_num, 1UL);
  ASSERT_EQ(params.wcis[0].operating_class, 17UL);
  ASSERT_EQ(params.wcis[0].chan_num, 172UL);
  ASSERT_EQ(params.wcis[0].transmit_power_level, kDot3Power_Min);
  ASSERT_EQ(params.wcis[0].datarate, kDot3DataRate_3Mbps);
  ASSERT_EQ(params.wcis[0].adaptable_datarate, false);
  ASSERT_FALSE(params.wcis[0].extension.chan_access);
  ASSERT_FALSE(params.wcis[0].extension.edca_param_set);
  ASSERT_FALSE(params.present.wra);

  // UAS 정보 확인
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr,
                                    wsa_type,
                                    rcpi,
                                    true, // available
                                    params.hdr.wsa_id,
                                    params.wsis[0].psid,
                                    params.wcis[params.wsis[0].channel_index-1].operating_class,
                                    params.wcis[params.wsis[0].channel_index-1].chan_num,
                                    params.wcis[params.wsis[0].channel_index-1].transmit_power_level,
                                    params.wcis[params.wsis[0].channel_index-1].datarate,
                                    params.wcis[params.wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   false, // advertiser_id
                                   false, // psc
                                   false, // ipv6 address
                                   false, // service port
                                   false, // provider mac address
                                   false, // rcpi threshold
                                   false, // wsa cnt threshold
                                   false, // wsa cnt threshold interval
                                   false, // edca parameter set
                                   false, // chan access
                                   false, // wra
                                   tx_lat,
                                   tx_lon,
                                   tx_elev,
                                   NULL, // advertiser_id
                                   NULL, // psc
                                   NULL, // ipv6 address
                                   0, // service port
                                   NULL, // provider mac address
                                   0, // rcpi threshold
                                   0, // wsa cnt threshold
                                   0, // wsa cnt threshold interval
                                   NULL, // edca parameter set
                                   0, // chan access
                                   NULL)); // wra
  free(set);

  Dot3_DeleteAllUASs();

  /*
   * 너무 작은 값을 전달하면 실패하는 것을 확인한다.
   */
  tx_elev = kDot3Elevation_Unavailable - 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidElevation);

  /*
   * 너무 큰 값을 전달하면 실패하는 것을 확인한다.
   */
  tx_elev = kDot3Elevation_Max + 1;
  // WSA 처리
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, -kDot3Result_InvalidElevation);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 이미 수신된 것과 동일한 WSA인 경우의 처리 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, IDENTICAL_WSA)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr[WSA_SENDER_NUM];
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Secured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록한다.
   */
  // g_min_wsa_with_no_ext 에 부합되는 USR
  SetUSRMandatoryInfo(psid[0], wsa_type[0], &usr[0]);
  ASSERT_EQ(Dot3_AddUSR(&usr[0]), 1);
  // g_max_wsa_with_all_ext 에 부합되는 USR
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  SetUSROptionalPSC("0123456789012345678901234567890", &usr[1]);
  SetUSROptionalSourceMACAddress(src_mac_addr[1], &usr[1]);
  SetUSROptionalAdvertiserID("01234567890123456789012345678901", &usr[1]);
  SetUSROptionalChannelNumber(174, &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 2);

  /*
   * WSA를 수신처리한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 생성된 UAS들이 정상적으로 반환되는 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[1],
                                    wsa_type[1],
                                    rcpi[1],
                                    false, // available
                                    params[1].hdr.wsa_id,
                                    params[1].wsis[0].psid,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   true, // advertiser_id
                                   true, // psc
                                   true, // ipv6 address
                                   true, // service port
                                   true, // provider mac address
                                   true, // rcpi threshold
                                   true, // wsa cnt threshold
                                   true, // wsa cnt threshold interval
                                   true, // edca parameter set
                                   true, // chan access
                                   true, // wra
                                   params[1].hdr.threed_location.latitude,
                                   params[1].hdr.threed_location.longitude,
                                   params[1].hdr.threed_location.elevation,
                                   &(params[1].hdr.advertiser_id), // advertiser_id
                                   &(params[1].wsis[0].psc), // psc
                                   params[1].wsis[0].ipv6_address, // ipv6 address
                                   params[1].wsis[0].service_port, // service port
                                   params[1].wsis[0].provider_mac_address, // provider mac address
                                   params[1].wsis[0].rcpi_threshold, // rcpi threshold
                                   params[1].wsis[0].wsa_cnt_threshold, // wsa cnt threshold
                                   params[1].wsis[0].wsa_cnt_threshold_interval, // wsa cnt threshold interval
                                   &(params[1].wcis[params[1].wsis[0].channel_index-1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index-1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  /*
   * 동일한 WSA를 또다시 수신처리한다.
   *  - RCPI만 변경한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1] + 1,
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 기존 UAS들이 정상적으로 반환되는 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[1],
                                    wsa_type[1],
                                    rcpi[1] + 1,
                                    false, // available
                                    params[1].hdr.wsa_id,
                                    params[1].wsis[0].psid,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   true, // advertiser_id
                                   true, // psc
                                   true, // ipv6 address
                                   true, // service port
                                   true, // provider mac address
                                   true, // rcpi threshold
                                   true, // wsa cnt threshold
                                   true, // wsa cnt threshold interval
                                   true, // edca parameter set
                                   true, // chan access
                                   true, // wra
                                   params[1].hdr.threed_location.latitude,
                                   params[1].hdr.threed_location.longitude,
                                   params[1].hdr.threed_location.elevation,
                                   &(params[1].hdr.advertiser_id), // advertiser_id
                                   &(params[1].wsis[0].psc), // psc
                                   params[1].wsis[0].ipv6_address, // ipv6 address
                                   params[1].wsis[0].service_port, // service port
                                   params[1].wsis[0].provider_mac_address, // provider mac address
                                   params[1].wsis[0].rcpi_threshold, // rcpi threshold
                                   params[1].wsis[0].wsa_cnt_threshold, // wsa cnt threshold
                                   params[1].wsis[0].wsa_cnt_threshold_interval, // wsa cnt threshold interval
                                   &(params[1].wcis[params[1].wsis[0].channel_index-1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index-1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 변경된 WSA의 수신 처리 동작을 확인한다.
 *  - 송신지 MAC 주소, WSA ID, 서비스정보는 동일하며, Content Count는 변경된 WSA
 */
TEST(Dot3_ProcessWSA, CHANGED_WSA)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr[WSA_SENDER_NUM];
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Secured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록한다.
   */
  // g_max_wsa_with_all_ext 에 부합되는 USR
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  SetUSROptionalPSC("0123456789012345678901234567890", &usr[1]);
  SetUSROptionalSourceMACAddress(src_mac_addr[1], &usr[1]);
  SetUSROptionalAdvertiserID("01234567890123456789012345678901", &usr[1]);
  SetUSROptionalChannelNumber(174, &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 1);

  /*
   * WSA를 수신처리한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 생성된 UAS들이 정상적으로 반환되는 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[1],
                                    wsa_type[1],
                                    rcpi[1],
                                    false, // available
                                    params[1].hdr.wsa_id,
                                    params[1].wsis[0].psid,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   true, // advertiser_id
                                   true, // psc
                                   true, // ipv6 address
                                   true, // service port
                                   true, // provider mac address
                                   true, // rcpi threshold
                                   true, // wsa cnt threshold
                                   true, // wsa cnt threshold interval
                                   true, // edca parameter set
                                   true, // chan access
                                   true, // wra
                                   params[1].hdr.threed_location.latitude,
                                   params[1].hdr.threed_location.longitude,
                                   params[1].hdr.threed_location.elevation,
                                   &(params[1].hdr.advertiser_id), // advertiser_id
                                   &(params[1].wsis[0].psc), // psc
                                   params[1].wsis[0].ipv6_address, // ipv6 address
                                   params[1].wsis[0].service_port, // service port
                                   params[1].wsis[0].provider_mac_address, // provider mac address
                                   params[1].wsis[0].rcpi_threshold, // rcpi threshold
                                   params[1].wsis[0].wsa_cnt_threshold, // wsa cnt threshold
                                   params[1].wsis[0].wsa_cnt_threshold_interval, // wsa cnt threshold interval
                                   &(params[1].wcis[params[1].wsis[0].channel_index-1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index-1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  /*
   * g_max_wsa_with_all_ext content count만 다른 WSA를 수신처리한다.
   *  - UAS가 제대로 업데이트 되었는지 확인하기 위해 rcpi를 다르게 전달한다.
   */
  uint8_t wsa_with_diff_content_cnt[967];
  memcpy(wsa_with_diff_content_cnt, g_max_wsa_with_all_ext, g_max_wsa_with_all_ext_size);
  wsa_with_diff_content_cnt[1] = 0xFE; // Content Count를 14로 변경
  ret = Dot3_ProcessWSA(wsa_with_diff_content_cnt,
                        sizeof(wsa_with_diff_content_cnt),
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1] + 1,
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 기존 UAS가 정상적으로 업데이트 된것을 확인한다. (새로 추가되지 않고)
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[1],
                                    wsa_type[1],
                                    rcpi[1] + 1,
                                    false, // available
                                    params[1].hdr.wsa_id,
                                    params[1].wsis[0].psid,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index-1].adaptable_datarate));
  ASSERT_TRUE(CheckUASOptionalInfo(uas,
                                   true, // advertiser_id
                                   true, // psc
                                   true, // ipv6 address
                                   true, // service port
                                   true, // provider mac address
                                   true, // rcpi threshold
                                   true, // wsa cnt threshold
                                   true, // wsa cnt threshold interval
                                   true, // edca parameter set
                                   true, // chan access
                                   true, // wra
                                   params[1].hdr.threed_location.latitude,
                                   params[1].hdr.threed_location.longitude,
                                   params[1].hdr.threed_location.elevation,
                                   &(params[1].hdr.advertiser_id), // advertiser_id
                                   &(params[1].wsis[0].psc), // psc
                                   params[1].wsis[0].ipv6_address, // ipv6 address
                                   params[1].wsis[0].service_port, // service port
                                   params[1].wsis[0].provider_mac_address, // provider mac address
                                   params[1].wsis[0].rcpi_threshold, // rcpi threshold
                                   params[1].wsis[0].wsa_cnt_threshold, // wsa cnt threshold
                                   params[1].wsis[0].wsa_cnt_threshold_interval, // wsa cnt threshold interval
                                   &(params[1].wcis[params[1].wsis[0].channel_index-1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index-1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시, 수신된 WSA의 일부 정보가 USR과 달라 UAS가 생성되지 않는 동작을 확인한다.
 *  - USR 등록 시 송신지MAC주소, 채널번호, PSC, Advertiser ID를 등록한다.
 *  - 해당 정보가 다른 WSA를 수신처리하는 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, USR_WITH_DIFFERENT_OPTIONAL_INFO)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr[WSA_SENDER_NUM];
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Secured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * g_max_wsa_with_all_ext 과 송신지 MAC 주소가 다른 USR을 등록한다.
   */
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  SetUSROptionalSourceMACAddress(src_mac_addr[0], &usr[1]);
  SetUSROptionalChannelNumber(174, &usr[1]);
  SetUSROptionalPSC("0123456789012345678901234567890", &usr[1]);
  SetUSROptionalAdvertiserID("01234567890123456789012345678901", &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 1);

  /*
   * WSA를 수신처리하면 UAS가 생성되지 않는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);

  /*
   * g_max_wsa_with_all_ext 과 채널번호가 다른 USR을 등록한다.
   */
  Dot3_DeleteAllUSRs();
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  SetUSROptionalSourceMACAddress(src_mac_addr[1], &usr[1]);
  SetUSROptionalChannelNumber(176, &usr[1]);
  SetUSROptionalPSC("0123456789012345678901234567890", &usr[1]);
  SetUSROptionalAdvertiserID("01234567890123456789012345678901", &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 1);

  /*
   * WSA를 수신처리하면 UAS가 생성되지 않는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);

  /*
   * g_max_wsa_with_all_ext 과 PSC가 다른 USR을 등록한다.
   */
  Dot3_DeleteAllUSRs();
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  SetUSROptionalSourceMACAddress(src_mac_addr[1], &usr[1]);
  SetUSROptionalChannelNumber(174, &usr[1]);
  SetUSROptionalPSC("012345678901234567890123456789", &usr[1]);
  SetUSROptionalAdvertiserID("01234567890123456789012345678901", &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 1);

  /*
   * WSA를 수신처리하면 UAS가 생성되지 않는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);

  /*
   * g_max_wsa_with_all_ext 과 Advertiser ID가 다른 USR을 등록한다.
   */
  Dot3_DeleteAllUSRs();
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  SetUSROptionalSourceMACAddress(src_mac_addr[1], &usr[1]);
  SetUSROptionalChannelNumber(174, &usr[1]);
  SetUSROptionalPSC("0123456789012345678901234567890", &usr[1]);
  SetUSROptionalAdvertiserID("0123456789012345678901234567890", &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 1);

  /*
   * WSA를 수신처리하면 UAS가 생성되지 않는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 UAS 테이블이 가득 차면 더이상 UAS가 생성되지 않는 것을 확인한다.
 *  - 하나의 WSA 샘플 데이터로 다수의 UAS를 생성하도록 하기 위해 다양한 송신지 MAC 주소를 사용하여 테스트한다.
 */
TEST(Dot3_ProcessWSA, UAS_TABLE_FULL)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr[WSA_SENDER_NUM];
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Secured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * g_max_wsa_with_all_ext에 부합하는 USR을 등록한다. (필수정보만 등록)
   */
  SetUSRMandatoryInfo(psid[1], wsa_type[1], &usr[1]);
  ASSERT_EQ(Dot3_AddUSR(&usr[1]), 1);

  /*
   * 송신지 MAC 주소를 다르게 전달하면, UAS 테이블이 가득 찰 때까지 UAS가 생성되는 것을 확인한다.
   */
  for (unsigned int i = 0; i < kDot3UASNum_Max; i++) {
    src_mac_addr[1][4] = (uint8_t)(i / 255);
    src_mac_addr[1][5] = (uint8_t)(i % 255);
    ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                          g_max_wsa_with_all_ext_size,
                          src_mac_addr[1],
                          wsa_type[1],
                          rcpi[1],
                          tx_lat[1],
                          tx_lon[1],
                          tx_elev[1],
                          &params[1]);
    ASSERT_EQ(ret, kDot3Result_Success);
  }
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, kDot3UASNum_Max);

  /*
   * UAS 테이블이 가득 찬 상태에서 한번 더 호출하면 UAS가 생성되지 않는 것을 확인한다.
   */
  src_mac_addr[1][3]++;
  ret = Dot3_ProcessWSA(g_max_wsa_with_all_ext,
                        g_max_wsa_with_all_ext_size,
                        src_mac_addr[1],
                        wsa_type[1],
                        rcpi[1],
                        tx_lat[1],
                        tx_lon[1],
                        tx_elev[1],
                        &params[1]);
  ASSERT_EQ(ret, -kDot3Result_UASTableFull);

  free(set);
  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 송신자 좌표 정보에 따른 동작을 확인한다.
 */
TEST(Dot3_ProcessWSA, LOCATION)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr[WSA_SENDER_NUM];
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Secured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Unavailable, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Unavailable, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Unavailable, kDot3Elevation_Unavailable};

  /*
   * USR을 등록한다. (필수정보만 등록)
   */
  SetUSRMandatoryInfo(psid[0], wsa_type[0], &usr[0]);
  ASSERT_EQ(Dot3_AddUSR(&usr[0]), 1);

  /*
   * 송신지 좌표 정보가 WSA 헤더에도 없고 전달되지도 않으면 UAS에 해당 정보가 없는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        kDot3Latitude_Unavailable,
                        kDot3Longitude_Unavailable,
                        kDot3Elevation_Unavailable,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->tx_lat, kDot3Latitude_Unavailable);
  ASSERT_EQ(uas->tx_lon, kDot3Longitude_Unavailable);
  ASSERT_EQ(uas->tx_elev, kDot3Elevation_Unavailable);
  free(set);
  Dot3_DeleteAllUASs();

  /*
   * 송신지 좌표 정보가 WSA 2DLocation 헤더에 있으면 파라미터로 전달되지 않아도 UAS에 해당 정보가 포함되는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_2d_location,
                        g_min_wsa_with_2d_location_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        kDot3Latitude_Unavailable,
                        kDot3Longitude_Unavailable,
                        kDot3Elevation_Unavailable,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->tx_lat, kDot3Latitude_Min);
  ASSERT_EQ(uas->tx_lon, kDot3Longitude_Min);
  ASSERT_EQ(uas->tx_elev, kDot3Elevation_Unavailable);
  free(set);
  Dot3_DeleteAllUASs();

  /*
   * 송신지 좌표 정보가 WSA 3DLocation 헤더에 있으면 파라미터로 전달되지 않아도 UAS에 해당 정보가 포함되는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_3d_location,
                        g_min_wsa_with_3d_location_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        kDot3Latitude_Unavailable,
                        kDot3Longitude_Unavailable,
                        kDot3Elevation_Unavailable,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->tx_lat, kDot3Latitude_Min);
  ASSERT_EQ(uas->tx_lon, kDot3Longitude_Min);
  ASSERT_EQ(uas->tx_elev, kDot3Elevation_Min);
  free(set);
  Dot3_DeleteAllUASs();

  /*
   * 송신지 좌표 정보가 WSA 헤더에도 존재하고 파라미터로도 전달되면 파라미터 값이 UAS에 포함되는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_3d_location,
                        g_min_wsa_with_3d_location_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        kDot3Latitude_Min + 1,
                        kDot3Longitude_Min + 1,
                        kDot3Elevation_Min + 1,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->tx_lat, kDot3Latitude_Min + 1);
  ASSERT_EQ(uas->tx_lon, kDot3Longitude_Min + 1);
  ASSERT_EQ(uas->tx_elev, kDot3Elevation_Min + 1);
  free(set);
  Dot3_DeleteAllUASs();

  ReleaseTestEnv();
}


/**
 * @brief Dot3_ProcessWSA() API 호출 시 RCPI threshold 및 RCPI 값에 따른 동작을 확ㅇ니한다.
 */
TEST(Dot3_ProcessWSA, RCPI_THRESHOLD)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr[WSA_SENDER_NUM];
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Secured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Unavailable, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Unavailable, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Unavailable, kDot3Elevation_Unavailable};

  /*
   * USR을 등록한다. (필수정보만 등록)
   */
  SetUSRMandatoryInfo(psid[0], wsa_type[0], &usr[0]);
  ASSERT_EQ(Dot3_AddUSR(&usr[0]), 1);

  /*
   * WSA에 포함된 RCPI threshold보다 작은 RCPI로 수신되면 생성된 UAS의 상태가 유효하지 않은 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_rcpi_threshold_10,
                        g_min_wsa_with_rcpi_threshold_10_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        9UL,
                        kDot3Latitude_Unavailable,
                        kDot3Longitude_Unavailable,
                        kDot3Elevation_Unavailable,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->rcpi_threshold, 10UL);
  ASSERT_EQ(uas->rcpi, 9UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA에 포함된 RCPI threshold보다 크거나 같은 RCPI로 수신되면 UAS의 상태가 유효해 지는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_rcpi_threshold_10,
                        g_min_wsa_with_rcpi_threshold_10_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        10UL,
                        kDot3Latitude_Unavailable,
                        kDot3Longitude_Unavailable,
                        kDot3Elevation_Unavailable,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->rcpi_threshold, 10UL);
  ASSERT_EQ(uas->rcpi, 10UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * 다시 RCPI threshold보다 작은 RCPI로 수신되면 UAS의 상태가 유효하지 않게 되는 것을 확인한다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_rcpi_threshold_10,
                        g_min_wsa_with_rcpi_threshold_10_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        9UL,
                        kDot3Latitude_Unavailable,
                        kDot3Longitude_Unavailable,
                        kDot3Elevation_Unavailable,
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->rcpi_threshold, 10UL);
  ASSERT_EQ(uas->rcpi, 9UL);
  ASSERT_FALSE(uas->available);
  free(set);

  ReleaseTestEnv();
}
