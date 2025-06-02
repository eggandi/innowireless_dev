/** 
 * @file
 * @brief UAS 관리기능에 대한 단위테스트
 * @date 2020-08-01
 * @author gyun
 */


// 시스템 헤더 파일
#include <unistd.h>

// 라이브러리 헤더 파일
#include <dot3/dot3-types.h>
#include "dot3-2016/dot3.h"

// google test 헤더 파일
#include "gtest/gtest.h"
#include "../test-libdot3.h"


/**
 * @brief UAS가 만기되면 삭제되는 것을 확인한다.
 */
TEST(UAS_MGMT, REMOVE_UAS_WHEN_EXPIRED)
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
  usr.psid = 0;
  usr.wsa_type = kDot3WSAType_Unsecured;
  ASSERT_EQ(Dot3_AddUSR(&usr), 1);

  /*
   * UAS 관리 기능을 시작한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Default), kDot3Result_Success);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
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

  /*
   * UAS가 생성된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  free(set);

  /*
   * UAS 만기 시점(DOT3_UAS_EXPIRY_TIME)보다 조금 더 기다린다.
   */
  sleep(5+1);

  /*
   * 더 이상 UAS가 존재하지 않는 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief WSA count 값에 따라 UAS의 유효성 판단 동작을 확인한다.
 *  - 조건: 100msec 당 1개 수신
 */
TEST(UAS_MGMT, VALIDATE_WSA_COUNT_1_PER_100)
{
  extern uint8_t g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100[];
  extern size_t g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100_size;

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
   * UAS 관리 기능을 시작한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Default), kDot3Result_Success);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100,
                        g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기인 1초가 되기 전에 9개의 WSA를 추가 수신처리한다.
   */
  for (unsigned int i = 0; i < 9; i++) {
    ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100,
                          g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100_size,
                          src_mac_addr,
                          wsa_type,
                          rcpi,
                          tx_lat,
                          tx_lon,
                          tx_elev,
                          &params);
    ASSERT_EQ(ret, kDot3Result_Success);
  }

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1500000);

  /*
   * UAS가 유효 상태가 된 것을 확인한다.
   *  - 100msec 마다 1개의 WSA가 수신되어야 하는 것이 조건이다. 1초 동안 10개의 WSA가 수신되었으므로 조건에 만족하였다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1500000);

  /*
   * UAS가 다시 유효하지 않은 상태가 된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA를 다시 수신처리한다.
   */
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100,
                        g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기인 1초가 되기 전에 8개의 WSA를 추가 수신처리한다.
   */
  for (unsigned int i = 0; i < 8; i++) {
    ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100,
                          g_abnormal_wsa_with_wsa_cnt_threshold_1_per_100_size,
                          src_mac_addr,
                          wsa_type,
                          rcpi,
                          tx_lat,
                          tx_lon,
                          tx_elev,
                          &params);
    ASSERT_EQ(ret, kDot3Result_Success);
  }

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1500000);

  /*
   * UAS가 유효 상태가 되지 않은 것을 확인한다.
   *  - 100msec 마다 1개의 WSA가 수신되어야 하는 것이 조건이다. 1초 동안 9개의 WSA가 수신되었으므로 조건에 만족하였다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * UAS 만기시점까지 기다린다.
   */
  usleep(5500000);

  /*
   * UAS가 삭제된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief WSA count 값에 따라 UAS의 유효성 판단 동작을 확인한다.
 *  - 조건: 1000msec당 3개 수신
 */
TEST(UAS_MGMT, VALIDATE_WSA_COUNT_3_PER_1000)
{
  extern uint8_t g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000[];
  extern size_t g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000_size;

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
   * UAS 관리 기능을 시작한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Default), kDot3Result_Success);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기인 1초가 되기 전에 2개의 WSA를 추가 수신처리한다.
   */
  for (unsigned int i = 0; i < 2; i++) {
    ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000,
                          g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000_size,
                          src_mac_addr,
                          wsa_type,
                          rcpi,
                          tx_lat,
                          tx_lon,
                          tx_elev,
                          &params);
    ASSERT_EQ(ret, kDot3Result_Success);
  }

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1100000);

  /*
   * UAS가 유효 상태가 된 것을 확인한다.
   *  - 1000msec 마다 3개의 WSA가 수신되어야 하는 것이 조건이다. 1초 동안 3개의 WSA가 수신되었으므로 조건에 만족하였다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1100000);

  /*
   * UAS가 다시 유효하지 않은 상태가 된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA를 다시 수신처리한다.
   */
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기인 1초가 되기 전에 2개의 WSA를 추가 수신처리한다.
   */
  for (unsigned int i = 0; i < 2; i++) {
    ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000,
                          g_abnormal_wsa_with_wsa_cnt_threshold_3_per_1000_size,
                          src_mac_addr,
                          wsa_type,
                          rcpi,
                          tx_lat,
                          tx_lon,
                          tx_elev,
                          &params);
    ASSERT_EQ(ret, kDot3Result_Success);
  }

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1100000);

  /*
   * UAS가 다시 유효한 상태가 된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * UAS 만기시점까지 기다린다.
   */
  usleep(5100000);

  /*
   * UAS가 삭제된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}


/**
 * @brief WSA count 값에 따라 UAS의 유효성 판단 동작을 확인한다.
 *  - 조건: 2000msec당 10개 수신
 */
TEST(UAS_MGMT, VALIDATE_WSA_COUNT_10_PER_2000)
{
  extern uint8_t g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000[];
  extern size_t g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000_size;

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
   * UAS 관리 기능을 시작한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Default), kDot3Result_Success);

  /*
   * WSA를 수신처리한다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 10;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000,
                        g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA Count threshold interval인 2초가 되기 전에 9개의 WSA를 추가 수신처리한다.
   */
  for (unsigned int i = 0; i < 9; i++) {
    ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000,
                          g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000_size,
                          src_mac_addr,
                          wsa_type,
                          rcpi,
                          tx_lat,
                          tx_lon,
                          tx_elev,
                          &params);
    ASSERT_EQ(ret, kDot3Result_Success);
  }

  /*
   * 타이머 1주기만큼 기다린 후 확인하면 여전히 유효하지 않은 상태인 것을 확인한다.
   */
  usleep(1100000);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기만큼 더 기다려서 WSA count threshold interval인 2초를 채운다.
   */
  usleep(1100000);

  /*
   * UAS가 유효 상태가 된 것을 확인한다.
   *  - 2000msec 마다 10개의 WSA가 수신되어야 하는 것이 조건이다. 2초 동안 10개의 WSA가 수신되었으므로 조건에 만족하였다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * 타이머 1주기만큼 기다린 후 확인하면 여전히 유효한 상태인 것을 확인한다.
   */
  usleep(1100000);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * 타이머 1주기만큼 더 기다려서 WSA count threshold interval인 2초를 채운다.
   */
  usleep(1100000);

  /*
   * UAS가 다시 유효하지 않은 상태가 된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA를 다시 수신처리한다.
   */
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000,
                        g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000_size,
                        src_mac_addr,
                        wsa_type,
                        rcpi,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA count threshold interval인 2초가 되기 전에 9개의 WSA를 추가 수신처리한다.
   */
  for (unsigned int i = 0; i < 9; i++) {
    ret = Dot3_ProcessWSA(g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000,
                          g_abnormal_wsa_with_wsa_cnt_threshold_10_per_2000_size,
                          src_mac_addr,
                          wsa_type,
                          rcpi,
                          tx_lat,
                          tx_lon,
                          tx_elev,
                          &params);
    ASSERT_EQ(ret, kDot3Result_Success);
  }

  /*
   * WSA count threshold interval인 2초 후에 UAS가 다시 유효한 상태가 된 것을 확인한다.
   */
  usleep(2100000);
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * UAS 만기시점까지 기다린다.
   */
  usleep(5100000);

  /*
   * UAS가 삭제된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}



/**
 * @brief RCPI 및 WSA count 값에 따라 UAS의 유효성 판단 동작을 확인한다.
 *  - WSA count 조건: 1000msec당 3개 수신
 *  - 유효성 판단 시점에 RCPI 조건 및 WSA count 조건을 만족해야 UAS가 유효해 진다.
 *  - RCPI에 따른 유효성은 유효성 판단 시점 기준으로 가장 최근에 수신된 WSA의 RCPI를 기준으로 한다.
 */
TEST(UAS_MGMT, VALIDATE_RCPI_AND_WSA_COUNT_THRESHOLD)
{
  extern uint8_t g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000[];
  extern size_t g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size;

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
   * UAS 관리 기능을 시작한다.
   */
  ASSERT_EQ(Dot3_StartUASManagement(kDot3UASManagementInterval_Default), kDot3Result_Success);

  /*
   * WSA를 수신처리한다.
   *  - RCPI 값은 threshold 보다 작다.
   */
  uint8_t src_mac_addr[MAC_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  Dot3WSAType wsa_type = kDot3WSAType_Unsecured;
  Dot3RCPI rcpi = 9;
  Dot3Latitude tx_lat = kDot3Latitude_Min;
  Dot3Longitude tx_lon = kDot3Longitude_Min;
  Dot3Elevation tx_elev = kDot3Elevation_Min;
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        9,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기인 1초가 되기 전에 2개의 WSA를 추가 수신처리한다.
   *  - 마지막 WSA는 RCPI threhold와 같은 RCPI로 수신한다.
   *  - RCPI 기준은 유효성 판단시점 기준 가장 최근의 RCPI만 사용되므로, RCPI 기준은 만족한 상태가 된다.
   */
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        9,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        10,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1100000);

  /*
   * UAS가 유효 상태가 된 것을 확인한다.
   *  - 마지막 수신된 WSA의 RCPI가 기준값과 동일하므로 조건에 만족하였다.
   *  - 1000msec 마다 3개의 WSA가 수신되어야 하는 것이 조건이다. 1초 동안 3개의 WSA가 수신되었으므로 조건에 만족하였다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_TRUE(uas->available);
  free(set);

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1100000);

  /*
   * UAS가 다시 유효하지 않은 상태가 된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * WSA를 다시 수신처리한다.
   *  - RCPI 는 threshold 값과 동일하게 수신한다.
   */
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        10,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * UAS가 생성되었지만 유효하지 않은 상태인 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * 타이머 1주기인 1초가 되기 전에 2개의 WSA를 추가 수신처리한다.
   *  - 마지막은 RCPI threshold보다 작은 세기로 수신한다.
   *  - RCPI 기준은 유효성 판단시점 기준 가장 최근의 RCPI만 사용되므로, RCPI 기준은 만족하지 못한 상태가 된다.
   *  - 결론적으로, WSA count 기준은 만족하였으나 RCPI 기준은 만족하지 못했다.
   */
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        10,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);
  ret = Dot3_ProcessWSA(g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000,
                        g_abnormal_wsa_with_rcpi_and_wsa_cnt_threshold_3_per_1000_size,
                        src_mac_addr,
                        wsa_type,
                        9,
                        tx_lat,
                        tx_lon,
                        tx_elev,
                        &params);
  ASSERT_EQ(ret, kDot3Result_Success);

  /*
   * 타이머 1주기보다 조금더 기다린다.
   */
  usleep(1100000);

  /*
   * UAS가 유효하지 않은 것을 확인한다.
   *  - 마지막 수신된 WSA의 RCPI가 기준값보다 작으므로 조건을 만족하지 못했다.
   *  - 1000msec 마다 3개의 WSA가 수신되어야 하는 것이 조건이다. 1초 동안 3개의 WSA가 수신되었으므로 조건에 만족하였다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 1UL);
  uas = set->uas;
  ASSERT_EQ(uas->psid, 0UL);
  ASSERT_FALSE(uas->available);
  free(set);

  /*
   * UAS 만기시점까지 기다린다.
   */
  usleep(5100000);

  /*
   * UAS가 삭제된 것을 확인한다.
   */
  set = Dot3_GetAllUASs(&ret);
  ASSERT_TRUE(set != NULL);
  ASSERT_EQ(set->num, 0UL);
  free(set);

  ReleaseTestEnv();
}
