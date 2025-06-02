/** 
 * @file
 * @brief 입력되는 사용자 GNSS 데이터가 BSM에 정확하게 반영되는지 시험하는 단위테스트 구현 파일
 * @date 2020-10-09
 * @author gyun
 */


// 의존 헤더 파일
#include "sudo_queue.h"
#if defined(_OBJASN1C_)
#include "DSRC.h"
#endif

// 라이브러리 헤더 파일
#include "j29451/j29451.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/*
 * 입력된 사용자 GNSS 데이터가 정상적으로 BSM에 수납되는 것을 확인한다.
 */
TEST(CHECK_USER_GNSS_DATA_IN_BSM, FIRST_BSM)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * BSM이 전송될 수 있도록 최소필요 샘플 차량정보를 입력한다.
   */
  g_j29451_mib.vehicle.size.width = TEST_VEHICLE_INFO_INITIAL_WIDTH;
  g_j29451_mib.vehicle.size.length = TEST_VEHICLE_INFO_INITIAL_LENGTH;

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  /*
   * 사용자 GNSS 데이터를 설정한다.
   */
  J29451Latitude lat = kJ29451Latitude_Min + 1;
  J29451Longitude lon = kJ29451Longitude_Min + 2;
  J29451Elevation elev = kJ29451Elevation_Min + 3;
  J29451Speed speed = J29451_SPEED_THRESH_LATCH_HEADING; // Heading latching 발생되지 않는 속도로만 테스트
  J29451Heading heading = kJ29451Heading_Min + 5;
  J29451SemiMajorAxisAccuracy smajor = kJ29451SemiMajorAxisAccuracy_Min + 6;
  J29451SemiMinorAxisAccuracy sminor = kJ29451SemiMinorAxisAccuracy_Min + 7;
  J29451SemiMajorAxisOrientation orientation = kJ29451SemiMajorAxisOrientation_Min + 8;
  J29451Acceleration accel_lon = kJ29451Acceleration_Max; // hard braking 이벤트 발생을 방지하기 위해 양수로만 테스트
  J29451Acceleration accel_lat = kJ29451Acceleration_Min + 9;
  J29451VerticalAcceleration accel_vert = kJ29451VerticalAcceleration_Min + 11;
  J29451YawRate accel_yaw = kJ29451YawRate_Min + 12;
  ASSERT_EQ(J29451_SetUserGNSSLatitude(lat), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSLongitude(lon), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSElevation(elev), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
  ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(smajor, sminor, orientation), kJ29451Result_Success);
  J29451_SetUserGNSSAccelerationSet4Way(accel_lon, accel_lat, accel_vert, accel_yaw);


  /*
   * 콜백함수로 전달된 BSM 내에, 설정한 정보가 정상적으로 수납된 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  /*
   * BSM 디코딩 및 데이터 비교 - 사용자 입력 GNSS 데이터가 정상적으로 수납되었는지 확인한다.
   */
#if defined(_OBJASN1C_)
  OSCTXT ctxt;
  rtInitContext(&ctxt);
  pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
  MessageFrame frame;
  ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
  ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
  BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;

  // 설정한 사용자 입력 GNSS 데이터가 맞는지 확인
  ASSERT_EQ(bsm->coreData.lat, lat);
  ASSERT_EQ(bsm->coreData.long_, lon);
  ASSERT_EQ(bsm->coreData.elev, elev);
  ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)smajor);
  ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)sminor);
  ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)orientation);
  ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm->coreData.speed, speed);
  ASSERT_EQ(bsm->coreData.heading, heading);
  ASSERT_EQ(bsm->coreData.accelSet.long_, (int)accel_lat);
  ASSERT_EQ(bsm->coreData.accelSet.lat, (int)accel_lon);
  ASSERT_EQ(bsm->coreData.accelSet.vert, (int)accel_vert);
  ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)accel_yaw);

  ASSERT_TRUE(bsm->m.partIIPresent);
  OSRTDListNode *node = bsm->partII.head;
  auto *content = (BasicSafetyMessage_partII_element *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  VehicleSafetyExtensions *ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
  ASSERT_FALSE(ext->m.eventsPresent);
  ASSERT_TRUE(ext->m.pathHistoryPresent);
  ASSERT_TRUE(ext->m.pathPredictionPresent);
  ASSERT_FALSE(ext->m.lightsPresent);
#else
  pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
  BasicSafetyMessage bsm;
  ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);

  // 설정한 사용자 입력 GNSS 데이터가 맞는지 확인
  ASSERT_EQ(bsm.coreData.lat, lat);
  ASSERT_EQ(bsm.coreData.long_, lon);
  ASSERT_EQ(bsm.coreData.elev, elev);
  ASSERT_EQ(bsm.coreData.accuracy.semiMajor, (int)smajor);
  ASSERT_EQ(bsm.coreData.accuracy.semiMinor, (int)sminor);
  ASSERT_EQ(bsm.coreData.accuracy.orientation, (int)orientation);
  ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm.coreData.speed, speed);
  ASSERT_EQ(bsm.coreData.heading, heading);
  ASSERT_EQ(bsm.coreData.accelSet.long_, (int)accel_lat);
  ASSERT_EQ(bsm.coreData.accelSet.lat, (int)accel_lon);
  ASSERT_EQ(bsm.coreData.accelSet.vert, (int)accel_vert);
  ASSERT_EQ(bsm.coreData.accelSet.yaw, (int)accel_yaw);

  ASSERT_TRUE(bsm.m.partIIPresent);
  OSRTDListNode *node = bsm.partII.head;
  PartIIcontent *content = (PartIIcontent *)(node->data);
  ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
  pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
  VehicleSafetyExtensions ext;
  ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
  ASSERT_FALSE(ext.m.eventsPresent);
  ASSERT_TRUE(ext.m.pathHistoryPresent);
  ASSERT_TRUE(ext.m.pathPredictionPresent);
  ASSERT_FALSE(ext.m.lightsPresent);
#endif
  rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
  j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
  ASSERT_TRUE(msg != nullptr);
  auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);

  // 설정한 사용자 입력 GNSS 데이터가 맞는지 확인
  ASSERT_EQ(bsm->coreData.lat, lat);
  ASSERT_EQ(bsm->coreData.Long, lon);
  ASSERT_EQ(bsm->coreData.elev, elev);
  ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)smajor);
  ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)sminor);
  ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)orientation);
  ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm->coreData.speed, (int)speed);
  ASSERT_EQ(bsm->coreData.heading, (int)heading);
  ASSERT_EQ(bsm->coreData.accelSet.Long, (int)accel_lon);
  ASSERT_EQ(bsm->coreData.accelSet.lat, (int)accel_lat);
  ASSERT_EQ(bsm->coreData.accelSet.vert, (int)accel_vert);
  ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)accel_yaw);

  ASSERT_TRUE(bsm->partII_option);
  auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts != nullptr);
  ASSERT_FALSE(exts->events_option);
  ASSERT_TRUE(exts->pathHistory_option); // per j2945/1
  ASSERT_FALSE(exts->pathHistory.initialPosition_option); // per j2945/1
  ASSERT_FALSE(exts->pathHistory.currGNSSstatus_option); // per j2945/1
  ASSERT_TRUE(exts->pathPrediction_option); // per j2945/1
  ASSERT_FALSE(exts->lights_option);

  J29451_FreeDecodedMessageFrame(msg);
#endif
  J29451Test_ReleaseEnv();
}


/*
 * 입력된 사용자 GNSS 데이터가 정상적으로 BSM에 수납되는 것을 확인한다.
 */
TEST(CHECK_USER_GNSS_DATA_IN_BSM, MULTIPLE_BSM)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Err, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * 사용자 GNSS 입력을 활성화한다.
   */
  J29451_EnableUserGNSSData();

  /*
   * BSM이 전송될 수 있도록 최소필요 샘플 차량정보를 입력한다.
   */
  g_j29451_mib.vehicle.size.width = TEST_VEHICLE_INFO_INITIAL_WIDTH;
  g_j29451_mib.vehicle.size.length = TEST_VEHICLE_INFO_INITIAL_LENGTH;

  /*
   * BSM 송신을 시작한다.
   */
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  unsigned int entry_num = 0;

  /*
   * 이 후 BSM 전송시점전마다 샘플 사용자 입력 GNSS 데이터를 업데이트 한다.
   */
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
  for (unsigned int i = 0; i < TEST_GNSS_DATA_NUM; i++) {
    lat = ((lat + 1) >= kJ29451Latitude_Max) ? kJ29451Latitude_Min : lat + 1;
    lon = ((lon + 1) >= kJ29451Longitude_Max) ? kJ29451Longitude_Min : lon + 1;
    elev = ((elev + 1) >= kJ29451Elevation_Max) ? kJ29451Elevation_Min : elev + 1;
    speed = ((speed + 1) >= kJ29451Speed_Max) ? J29451_SPEED_THRESH_LATCH_HEADING : speed + 1; // Heading latching 발생되지 않는 속도로만 테스트
    heading = ((heading + 1) >= kJ29451Heading_Max) ? kJ29451Heading_Min : heading + 1;
    smajor = ((smajor + 1) >= kJ29451SemiMajorAxisAccuracy_Max) ? kJ29451SemiMajorAxisAccuracy_Min : smajor + 1;
    sminor = ((sminor + 1) >= kJ29451SemiMinorAxisAccuracy_Max) ? kJ29451SemiMinorAxisAccuracy_Min : sminor + 1;
    orientation = ((orientation + 1) >= kJ29451SemiMajorAxisOrientation_Max) ? kJ29451SemiMajorAxisOrientation_Min : orientation + 1;
    accel_lon = ((accel_lon + 1) >= kJ29451Acceleration_Max) ? 0 : accel_lon + 1; // hard braking 이벤트 발생을 방지하기 위해 양수로만 테스트
    accel_lat = ((accel_lat + 1) >= kJ29451Acceleration_Max) ? kJ29451Acceleration_Min : accel_lat + 1;
    accel_vert = ((accel_vert + 1) >= kJ29451VerticalAcceleration_Max) ? kJ29451VerticalAcceleration_Min : accel_vert + 1;
    accel_yaw = ((accel_yaw + 1) >= kJ29451YawRate_Max) ? kJ29451YawRate_Min : accel_yaw + 1;
    ASSERT_EQ(J29451_SetUserGNSSLatitude(lat), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSLongitude(lon), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSElevation(elev), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSSpeed(speed), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSHeading(heading), kJ29451Result_Success);
    ASSERT_EQ(J29451_SetUserGNSSPositionalAccuracy(smajor, sminor, orientation), kJ29451Result_Success);
    J29451_SetUserGNSSAccelerationSet4Way(accel_lon, accel_lat, accel_vert, accel_yaw);
    while(g_bsm_callback_list.entry_num == entry_num);
    entry_num++;
  }

  /*
   * BSM 전송을 중지한다.
   */
  J29451_StopBSMTransmit();

  /*
   * BSM에 수납된 정보를 확인한다.
   */
  lat = kJ29451Latitude_Min;
  lon = kJ29451Longitude_Min;
  elev = kJ29451Elevation_Min;
  speed = J29451_SPEED_THRESH_LATCH_HEADING; // Heading latching 발생되지 않는 속도로만 테스트
  heading = kJ29451Heading_Min;
  smajor = kJ29451SemiMajorAxisAccuracy_Min;
  sminor = kJ29451SemiMinorAxisAccuracy_Min;
  orientation = kJ29451SemiMajorAxisOrientation_Min;
  accel_lon = 0; // hard braking 이벤트 발생을 방지하기 위해 양수로만 테스트
  accel_lat = kJ29451Acceleration_Min;
  accel_vert = kJ29451VerticalAcceleration_Min;
  accel_yaw = kJ29451YawRate_Min;
  unsigned int init_msg_cnt;
  for (unsigned int i = 0; i < TEST_GNSS_DATA_NUM; i++)
  {
    if (i == 0) {
      entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
      ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM
    } else {
      entry = TAILQ_NEXT(entry, entries);
      ASSERT_FALSE(entry->cert_sign);
    }
    ASSERT_TRUE(entry != nullptr);
    ASSERT_FALSE(entry->id_change);
    ASSERT_FALSE(entry->event);

    /*
     * BSM 디코딩 및 데이터 비교 - 사용자 입력 GNSS 데이터가 정상적으로 수납되었는지 확인한다.
     */
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    if (i == 0) {
      init_msg_cnt = bsm->coreData.msgCnt;
    } else {
      ASSERT_EQ(bsm->coreData.msgCnt, (int)((init_msg_cnt + i) % 128));
    }

    // 설정한 사용자 입력 GNSS 데이터가 맞는지 확인
    lat = ((lat + 1) >= kJ29451Latitude_Max) ? kJ29451Latitude_Min : lat + 1;
    lon = ((lon + 1) >= kJ29451Longitude_Max) ? kJ29451Longitude_Min : lon + 1;
    elev = ((elev + 1) >= kJ29451Elevation_Max) ? kJ29451Elevation_Min : elev + 1;
    speed = ((speed + 1) >= kJ29451Speed_Max) ? kJ29451Speed_Min : speed + 1;
    heading = ((heading + 1) >= kJ29451Heading_Max) ? kJ29451Heading_Min : heading + 1;
    smajor = ((smajor + 1) >= kJ29451SemiMajorAxisAccuracy_Max) ? kJ29451SemiMajorAxisAccuracy_Min : smajor + 1;
    sminor = ((sminor + 1) >= kJ29451SemiMinorAxisAccuracy_Max) ? kJ29451SemiMinorAxisAccuracy_Min : sminor + 1;
    orientation = ((orientation + 1) >= kJ29451SemiMajorAxisOrientation_Max) ? kJ29451SemiMajorAxisOrientation_Min : orientation + 1;
    accel_lat = ((accel_lat + 1) >= kJ29451Acceleration_Max) ? kJ29451Acceleration_Min : accel_lat + 1;
    accel_lon = ((accel_lon + 1) >= kJ29451Acceleration_Max) ? kJ29451Acceleration_Min : accel_lon + 1;
    accel_vert = ((accel_vert + 1) >= kJ29451VerticalAcceleration_Max) ? kJ29451VerticalAcceleration_Min : accel_vert + 1;
    accel_yaw = ((accel_yaw + 1) >= kJ29451YawRate_Max) ? kJ29451YawRate_Min : accel_yaw + 1;
    ASSERT_EQ(bsm->coreData.lat, (int)lat);
    ASSERT_EQ(bsm->coreData.long_, (int)lon);
    ASSERT_EQ(bsm->coreData.elev, (int)elev);
    ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)smajor);
    ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)sminor);
    ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)orientation);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading);
    ASSERT_EQ(bsm->coreData.accelSet.long_, (int)accel_lon);
    ASSERT_EQ(bsm->coreData.accelSet.lat, (int)accel_lat);
    ASSERT_EQ(bsm->coreData.accelSet.vert, (int)accel_vert);
    ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)accel_yaw);
    ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);

    ASSERT_TRUE(bsm->m.partIIPresent);
    OSRTDListNode *node = bsm->partII.head;
    auto *content = (BasicSafetyMessage_partII_element *)(node->data);
    ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
    VehicleSafetyExtensions *ext = content->partII_Value.u._BSMpartIIExtension_vehicleSafetyExt;
    ASSERT_FALSE(ext->m.eventsPresent);
    ASSERT_TRUE(ext->m.pathHistoryPresent);
    ASSERT_TRUE(ext->m.pathPredictionPresent);
    ASSERT_FALSE(ext->m.lightsPresent);
#else
    pu_setBuffer(&ctxt, (OSOCTET *)(frame.value.data), frame.value.numocts, false);
    BasicSafetyMessage bsm;
    ASSERT_EQ(asn1PD_BasicSafetyMessage(&ctxt, &bsm), 0);
    if (i == 0) {
      init_msg_cnt = bsm.coreData.msgCnt;
    } else {
      ASSERT_EQ(bsm.coreData.msgCnt, (int)((init_msg_cnt + i) % 128));
    }

    // 설정한 사용자 입력 GNSS 데이터가 맞는지 확인
    ASSERT_EQ(bsm.coreData.lat, (int)(kJ29451Latitude_Min + i));
    ASSERT_EQ(bsm.coreData.long_, (int)(kJ29451Longitude_Min + i));
    ASSERT_EQ(bsm.coreData.elev, (int)(kJ29451Elevation_Min + i));
    ASSERT_EQ(bsm.coreData.accuracy.semiMajor, (int)(kJ29451SemiMajorAxisAccuracy_Min + i) % (kJ29451SemiMajorAxisAccuracy_Unavailable + 1));
    ASSERT_EQ(bsm.coreData.accuracy.semiMinor, (int)(kJ29451SemiMinorAxisAccuracy_Min + i) % (kJ29451SemiMinorAxisAccuracy_Unavailable + 1));
    ASSERT_EQ(bsm.coreData.accuracy.orientation, (int)(kJ29451SemiMajorAxisOrientation_Min + i));
    ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm.coreData.speed, (kJ29451Speed_Min + i));
    ASSERT_EQ(bsm.coreData.heading, (kJ29451Heading_Min + i));
    ASSERT_EQ(bsm.coreData.accelSet.long_, (int)(kJ29451Acceleration_Min + i));
    ASSERT_EQ(bsm.coreData.accelSet.lat, (int)(kJ29451Acceleration_Min + i));
    ASSERT_EQ(bsm.coreData.accelSet.vert, (int)(kJ29451VerticalAcceleration_Min + i));
    ASSERT_EQ(bsm.coreData.accelSet.yaw, (int)(kJ29451YawRate_Min + i));

    ASSERT_TRUE(bsm.m.partIIPresent);
    OSRTDListNode *node = bsm.partII.head;
    PartIIcontent *content = (PartIIcontent *)(node->data);
    ASSERT_EQ(content->partII_Id, 0); // = VehicleSafetyExtensions
    pu_setBuffer(&ctxt, (OSOCTET *)(content->partII_Value.data), content->partII_Value.numocts, false);
    VehicleSafetyExtensions ext;
    ASSERT_EQ(asn1PD_VehicleSafetyExtensions(&ctxt, &ext), 0);
    ASSERT_FALSE(ext.m.eventsPresent);
    ASSERT_TRUE(ext.m.pathHistoryPresent);
    ASSERT_TRUE(ext.m.pathPredictionPresent);
    ASSERT_FALSE(ext.m.lightsPresent);
#endif
    rtFreeContext(&ctxt);
#elif defined(_FFASN1C_)
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    if (i == 0) {
      init_msg_cnt = bsm->coreData.msgCnt;
    } else {
      ASSERT_EQ(bsm->coreData.msgCnt, (int)((init_msg_cnt + i) % 128));
    }

    // 설정한 사용자 입력 GNSS 데이터가 맞는지 확인
    lat = ((lat + 1) >= kJ29451Latitude_Max) ? kJ29451Latitude_Min : lat + 1;
    lon = ((lon + 1) >= kJ29451Longitude_Max) ? kJ29451Longitude_Min : lon + 1;
    elev = ((elev + 1) >= kJ29451Elevation_Max) ? kJ29451Elevation_Min : elev + 1;
    speed = ((speed + 1) >= kJ29451Speed_Max) ? J29451_SPEED_THRESH_LATCH_HEADING : speed + 1; // Heading latching 발생되지 않는 속도로만 테스트
    heading = ((heading + 1) >= kJ29451Heading_Max) ? kJ29451Heading_Min : heading + 1;
    smajor = ((smajor + 1) >= kJ29451SemiMajorAxisAccuracy_Max) ? kJ29451SemiMajorAxisAccuracy_Min : smajor + 1;
    sminor = ((sminor + 1) >= kJ29451SemiMinorAxisAccuracy_Max) ? kJ29451SemiMinorAxisAccuracy_Min : sminor + 1;
    orientation = ((orientation + 1) >= kJ29451SemiMajorAxisOrientation_Max) ? kJ29451SemiMajorAxisOrientation_Min : orientation + 1;
    accel_lon = ((accel_lon + 1) >= kJ29451Acceleration_Max) ? 0 : accel_lon + 1; // hard braking 이벤트 발생을 방지하기 위해 양수로만 테스트
    accel_lat = ((accel_lat + 1) >= kJ29451Acceleration_Max) ? kJ29451Acceleration_Min : accel_lat + 1;
    accel_vert = ((accel_vert + 1) >= kJ29451VerticalAcceleration_Max) ? kJ29451VerticalAcceleration_Min : accel_vert + 1;
    accel_yaw = ((accel_yaw + 1) >= kJ29451YawRate_Max) ? kJ29451YawRate_Min : accel_yaw + 1;
    ASSERT_EQ(bsm->coreData.lat, (int)lat);
    ASSERT_EQ(bsm->coreData.Long, (int)lon);
    ASSERT_EQ(bsm->coreData.elev, (int)elev);
    ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)smajor);
    ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)sminor);
    ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)orientation);
    ASSERT_EQ(bsm->coreData.speed, (int)speed);
    ASSERT_EQ(bsm->coreData.heading, (int)heading);
    ASSERT_EQ(bsm->coreData.accelSet.Long, (int)accel_lon);
    ASSERT_EQ(bsm->coreData.accelSet.lat, (int)accel_lat);
    ASSERT_EQ(bsm->coreData.accelSet.vert, (int)accel_vert);
    ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)accel_yaw);
    ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);

    ASSERT_TRUE(bsm->partII_option);
    auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
    auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
    ASSERT_TRUE(exts != nullptr);
    ASSERT_FALSE(exts->events_option);
    ASSERT_TRUE(exts->pathHistory_option); // per j2945/1
    ASSERT_FALSE(exts->pathHistory.initialPosition_option); // per j2945/1
    ASSERT_FALSE(exts->pathHistory.currGNSSstatus_option); // per j2945/1
    ASSERT_TRUE(exts->pathPrediction_option); // per j2945/1
    ASSERT_FALSE(exts->lights_option);

    J29451_FreeDecodedMessageFrame(msg);
#endif
  }

  J29451Test_ReleaseEnv();
}
