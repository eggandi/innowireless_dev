/** 
 * @file
 * @brief Dot3_GetUASsWithPSIDAndSourceMACAddress() API에 대한 단위테스트 구현 파일
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
 * @brief Dot3_GetUASsWithPSIDAndSourceMACAddress() API 호출 시 해당되는 UAS들이 정상적으로 반한되는 것을 확인한다.
 */
TEST(Dot3_GetUASsWithPSIDAndSourceMACAddress, NORMAL)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Unsecured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록한다.
   */
  for (unsigned int i = 0; i < WSA_SENDER_NUM; i++) {
    memset(&usr, 0, sizeof(usr));
    usr.psid = psid[i];
    usr.wsa_type = wsa_type[i];
    ret = Dot3_AddUSR(&usr);
    ASSERT_EQ(ret, (int)(i + 1));
  }

  /*
   * 서로 다른 송신지가 송신한 서로 다른 WSA를 수신처리한다.
   *  각 송신자가 전송하는 WSA는 포함된 PSID가 다르다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        tx_lat[0],
                        tx_lon[0],
                        tx_elev[0],
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
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
   * API 호출 시 원하는 UAS들이 정상적으로 반환되는 것을 확인한다.
   */
  // 첫번째 PSID & 송신자에 대한 UAS 확인
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], src_mac_addr[0], &ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[0],
                                    wsa_type[0],
                                    rcpi[0],
                                    true, // available
                                    params[0].hdr.wsa_id,
                                    params[0].wsis[0].psid,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].operating_class,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].chan_num,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].transmit_power_level,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].datarate,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].adaptable_datarate));
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
                                   tx_lat[0],
                                   tx_lon[0],
                                   tx_elev[0],
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

  // 두번째 PSID & 송신자에 대한 UAS 확인
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[1], src_mac_addr[1], &ret);
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
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].adaptable_datarate));
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
                                   &(params[1].wcis[params[1].wsis[0].channel_index -
                                                    1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index - 1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_GetUASsWithPSIDAndSourceMACAddress() API 호출 시 UAS 테이블에 UAS가 하나도 없을 때의 동작을 확인한다.
 */
TEST(Dot3_GetUASsWithPSIDAndSourceMACAddress, NO_UAS)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Unsecured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록하지 않는다.
   */

  /*
   * 서로 다른 송신지가 송신한 서로 다른 WSA를 수신처리한다.
   *  - 각 송신자가 전송하는 WSA는 포함된 PSID가 다르다.
   *  - USR이 등록되지 않았으므로 UAS가 생성되지 않는다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        tx_lat[0],
                        tx_lon[0],
                        tx_elev[0],
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
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
   * API 호출 시 0개의 UAS가 반환되는 것을 확인한다.
   */
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], src_mac_addr[0], &ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_GetUASsWithPSIDAndSourceMACAddress() API 호출 시 전달되는 src_mac_addr 파라미터 값에 따른 동작을 확인한다.
 */
TEST(Dot3_GetUASsWithPSIDAndSourceMACAddress, CHECK_PARAM_SRC_MAC_ADDR)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Unsecured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록한다.
   */
  for (unsigned int i = 0; i < WSA_SENDER_NUM; i++) {
    memset(&usr, 0, sizeof(usr));
    usr.psid = psid[i];
    usr.wsa_type = wsa_type[i];
    ret = Dot3_AddUSR(&usr);
    ASSERT_EQ(ret, (int)(i + 1));
  }

  /*
   * 서로 다른 송신지가 송신한 서로 다른 WSA를 수신처리한다.
   *  각 송신자가 전송하는 WSA는 포함된 PSID가 다르다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        tx_lat[0],
                        tx_lon[0],
                        tx_elev[0],
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
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
   * API 호출 시 원하는 UAS들이 정상적으로 반환되는 것을 확인한다.
   */
  // 첫번째 PSID & 송신자에 대한 UAS 확인
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], src_mac_addr[0], &ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[0],
                                    wsa_type[0],
                                    rcpi[0],
                                    true, // available
                                    params[0].hdr.wsa_id,
                                    params[0].wsis[0].psid,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].operating_class,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].chan_num,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].transmit_power_level,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].datarate,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].adaptable_datarate));
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
                                   tx_lat[0],
                                   tx_lon[0],
                                   tx_elev[0],
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

  // 두번째 PSID & 송신자에 대한 UAS 확인
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[1], src_mac_addr[1], &ret);
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
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].adaptable_datarate));
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
                                   &(params[1].wcis[params[1].wsis[0].channel_index -
                                                    1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index - 1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  /*
   * API 호출 시, 등록된 PSID와 등록되지 않은 송신지 MAC 주소를 전달하면 0개의 UAS가 반환되는 것을 확인한다.
   */
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], unknown_src_mac_addr, &ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_GetUASsWithPSIDAndSourceMACAddress() API 호출 시 전달되는 psid 파라미터 값에 따른 동작을 확인한다.
 */
TEST(Dot3_GetUASsWithPSIDAndSourceMACAddress, CHECK_PARAM_PSID)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Unsecured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록한다.
   */
  for (unsigned int i = 0; i < WSA_SENDER_NUM; i++) {
    memset(&usr, 0, sizeof(usr));
    usr.psid = psid[i];
    usr.wsa_type = wsa_type[i];
    ret = Dot3_AddUSR(&usr);
    ASSERT_EQ(ret, (int)(i + 1));
  }

  /*
   * 서로 다른 송신지가 송신한 서로 다른 WSA를 수신처리한다.
   *  각 송신자가 전송하는 WSA는 포함된 PSID가 다르다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        tx_lat[0],
                        tx_lon[0],
                        tx_elev[0],
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
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
   * API 호출 시 원하는 UAS들이 정상적으로 반환되는 것을 확인한다.
   */
  // 첫번째 PSID & 송신자에 대한 UAS 확인
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], src_mac_addr[0], &ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_TRUE(CheckUASMandatoryInfo(uas,
                                    src_mac_addr[0],
                                    wsa_type[0],
                                    rcpi[0],
                                    true, // available
                                    params[0].hdr.wsa_id,
                                    params[0].wsis[0].psid,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].operating_class,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].chan_num,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].transmit_power_level,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].datarate,
                                    params[0].wcis[params[0].wsis[0].channel_index - 1].adaptable_datarate));
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
                                   tx_lat[0],
                                   tx_lon[0],
                                   tx_elev[0],
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

  // 두번째 PSID & 송신자에 대한 UAS 확인
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[1], src_mac_addr[1], &ret);
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
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].operating_class,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].chan_num,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].transmit_power_level,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].datarate,
                                    params[1].wcis[params[1].wsis[0].channel_index - 1].adaptable_datarate));
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
                                   &(params[1].wcis[params[1].wsis[0].channel_index -
                                                    1].edca_param_set), // edca parameter set
                                   params[1].wcis[params[1].wsis[0].channel_index - 1].chan_access, // chan access
                                   &(params[1].wra))); // wra
  free(set);

  /*
   * API 호출 시, 등록되지 않은 PSID를 전달하면 0개의 UAS가 반환되는 것을 확인한다.
   */
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0] + 1, src_mac_addr[0], &ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief Dot3_GetUASsWithPSIDAndSourceMACAddress() API 호출 시 전달되는 NULL 파라미터에 따른 동작을 확인한다.
 */
TEST(Dot3_GetUASsWithPSIDAndSourceMACAddress, CHECK_PARAMS_NULL)
{
  InitTestEnv();

#define WSA_SENDER_NUM (2)

  int ret;
  struct Dot3USR usr;
  struct Dot3ParseWSAParams params[WSA_SENDER_NUM];
  struct Dot3UASSet *set;
  struct Dot3UAS *uas;

  uint8_t src_mac_addr[WSA_SENDER_NUM][MAC_ALEN] = {
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
  };
  uint8_t unknown_src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
  Dot3PSID psid[WSA_SENDER_NUM] = {kDot3PSID_Min, 15};
  Dot3WSAType wsa_type[WSA_SENDER_NUM] = { kDot3WSAType_Secured, kDot3WSAType_Unsecured };
  Dot3RCPI rcpi[WSA_SENDER_NUM] = { 10, 20 };
  Dot3Latitude tx_lat[WSA_SENDER_NUM] = {kDot3Latitude_Min, kDot3Latitude_Unavailable};
  Dot3Longitude tx_lon[WSA_SENDER_NUM] = {kDot3Longitude_Min, kDot3Longitude_Unavailable};
  Dot3Elevation tx_elev[WSA_SENDER_NUM] = {kDot3Elevation_Min, kDot3Elevation_Unavailable};

  /*
   * USR들을 등록한다.
   */
  for (unsigned int i = 0; i < WSA_SENDER_NUM; i++) {
    memset(&usr, 0, sizeof(usr));
    usr.psid = psid[i];
    usr.wsa_type = wsa_type[i];
    ret = Dot3_AddUSR(&usr);
    ASSERT_EQ(ret, (int)(i + 1));
  }

  /*
   * 서로 다른 송신지가 송신한 서로 다른 WSA를 수신처리한다.
   *  각 송신자가 전송하는 WSA는 포함된 PSID가 다르다.
   */
  ret = Dot3_ProcessWSA(g_min_wsa_with_no_ext,
                        g_min_wsa_with_no_ext_size,
                        src_mac_addr[0],
                        wsa_type[0],
                        rcpi[0],
                        tx_lat[0],
                        tx_lon[0],
                        tx_elev[0],
                        &params[0]);
  ASSERT_EQ(ret, kDot3Result_Success);
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
   * API 호출 시, src_mac_addr 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], NULL, &ret);
  ASSERT_TRUE(set == NULL);
  ASSERT_EQ(ret, -kDot3Result_NullParameters);

  /*
   * API 호출 시, err 파라미터를 NULL로 전달하면 실패하는 것을 확인한다.
   */
  set = Dot3_GetUASsWithPSIDAndSourceMACAddress(psid[0], src_mac_addr[0], NULL);
  ASSERT_TRUE(set == NULL);

  ReleaseTestEnv();
}
