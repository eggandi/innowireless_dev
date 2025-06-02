/**
 * @file
 * @brief BSM 데이터가 충분하지 않은 경우에 대해 시험하는 단위테스트 구현 파일
 * @date 2023-02-12
 * @author gyun
 */


// 시스템 헤더 파일
#include <math.h>

// 의존 헤더 파일
#include "sudo_queue.h"
#if defined(_OBJASN1C_)
#include "DSRC.h"
#endif

// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/*
 * Vehicle Size 정보가 없을 때 BSM이 전송되지 않는 것을 확인한다.
 */
TEST(INSUFFICIENT_DATA_IN_BSM, VEHICLE_SIZE)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 차량정보 입력없이 BSM 송신을 시작한다.
   */
  J29451BSMTxInterval tx_interval = kJ29451BSMTxInterval_Default;
  ASSERT_EQ(J29451_StartBSMTransmit(tx_interval), kJ29451Result_Success);

  /*
   * 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   *  - 차량정보가 부족하여 BSM을 전송할 수 없는 상황.
   */
  sleep(3);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  J29451Test_ReleaseEnv();
}


/*
 * GNSS 정보가 충분하지 않을 때 BSM이 전송되지 않는 것을 확인한다.
 */
TEST(INSUFFICIENT_DATA_IN_BSM, GNSS_DATA)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * BSM 송신을 시작한다.
   */
  J29451BSMTxInterval tx_interval = kJ29451BSMTxInterval_Default;
  ASSERT_EQ(J29451_StartBSMTransmit(tx_interval), kJ29451Result_Success);

  /*
   * yawrate 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].attitude.gyro_z = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * 종방향 가속도 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].attitude.acc_x = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * heading 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].fix.track = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * speed 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].fix.speed = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * Semi-major axis orientation 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].gst.smajor_orientation = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * Semi-minor axis accuracy 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].gst.sminor_deviation = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * Semi-major axis accuracy 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].gst.smajor_deviation = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * elevation 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].fix.altHAE = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * longitude 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].fix.longitude = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * latitude 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  for (int i = g_test_gps_data_idx; i < TEST_GNSS_DATA_NUM; i++) {
    g_test_gps_data[i].fix.latitude = NAN;
  }
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  J29451Test_ReleaseEnv();
}


/*
 * User GNSS 정보가 충분하지 않을 때 BSM이 전송되지 않는 것을 확인한다.
 */
TEST(INSUFFICIENT_DATA_IN_BSM, USER_GNSS_DATA)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화하고 입력한다.
   */
  J29451_EnableUserGNSSData();
  J29451Latitude lat = kJ29451Latitude_Min;
  J29451Longitude lon = kJ29451Longitude_Min;
  J29451Elevation elev = kJ29451Elevation_Min;
  J29451Speed speed = J29451_SPEED_THRESH_LATCH_HEADING; // Heading latching 발생되지 않는 속도로만 테스트
  J29451Heading heading = kJ29451Heading_Min;
  J29451SemiMajorAxisAccuracy smajor = kJ29451SemiMajorAxisAccuracy_Min;
  J29451SemiMinorAxisAccuracy sminor = kJ29451SemiMinorAxisAccuracy_Min;
  J29451SemiMajorAxisOrientation orientation = kJ29451SemiMajorAxisOrientation_Min;
  J29451Acceleration accel_lon = 0; // hard braking 이벤트 발생을 방지하기 위해 양수로만 테스트
  J29451Acceleration accel_lat = kJ29451Acceleration_Min;
  J29451VerticalAcceleration accel_vert = kJ29451VerticalAcceleration_Min;
  J29451YawRate accel_yaw = kJ29451YawRate_Min;
  ASSERT_EQ(J29451_SetUserGNSSLatitude(lat), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(lon), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSElevation(elev), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(smajor, sminor, orientation), kJ29451Result_Success);
  J29451_SetUserGNSSAccelerationSet4Way(accel_lon, accel_lat, accel_vert, accel_yaw);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * BSM 송신을 시작한다.
   */
  J29451BSMTxInterval tx_interval = kJ29451BSMTxInterval_Default;
  ASSERT_EQ(J29451_StartBSMTransmit(tx_interval), kJ29451Result_Success);

  /*
   * 종방향 가속도 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  J29451_SetUserGNSSAccelerationSet4Way(kJ29451Acceleration_Unavailable, accel_lat, accel_vert, accel_yaw);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * heading 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSHeading(kJ29451Heading_Unavailable), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * speed 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSSpeed(kJ29451Speed_Unavailable), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * Semi-major axis orientation 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(smajor, sminor, kJ29451SemiMajorAxisOrientation_Unavailable), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * Semi-minor axis accuracy 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(smajor, kJ29451SemiMinorAxisAccuracy_Unavailable, orientation), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * Semi-major axis accuracy 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(kJ29451SemiMajorAxisAccuracy_Unavailable, sminor, orientation), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * elevation 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSElevation(kJ29451Elevation_Unavailable), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * longitude 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLongitude(kJ29451Longitude_Unavailable), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * latitude 값이 유효하지 않을 경우, 오랜시간 기다려도 BSM이 전송되지 않는 것을 확인한다.
   */
  ASSERT_EQ(J29451_SetUserGNSSLatitude(kJ29451Latitude_Unavailable), kJ29451Result_Success);
  sleep(1);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  J29451Test_ReleaseEnv();
}

