/** 
 * @file
 * @brief 입력되는 GNSS 데이터가 BSM에 정확하게 반영되는지 시험하는 단위테스트 구현 파일
 * @date 2020-10-06
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
#include "j29451-internal-inline.h"
#include "j29451-mib.h"

// 단위테스트 헤더 파일
#include "gtest/gtest.h"
#include "../test-libj29451.h"


/*
 * 입력된 GNSS 데이터가 정상적으로 BSM에 수납되는 것을 확인한다.
 */
TEST(CHECK_GNSS_DATA_IN_BSM, FIRST_BSM)
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
   * BSM 전송이 시작되면서 콜백함수가 정상적으로 호출되는 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  /*
   * BSM 디코딩 및 데이터 비교 - 강제로 설정한 GPS 데이터가 맞게 수납되었는지 확인한다.
   * Path history를 생성하기 위해 최소한 과거 3개의 GNSS 정보가 필요하므로, 4번째 GNSS 데이터가 확보된 이후에 첫번째 BSM이 송신된다.
   * 따라서 첫번째 BSM의 CoreData에는 4번째 GNSS 데이터 정보가 포함되어 있다.
   */
  {
#if defined(_OBJASN1C_)
    OSCTXT ctxt;
    rtInitContext(&ctxt);
    pu_setBuffer(&ctxt, (OSOCTET *)(entry->bsm), entry->bsm_size, false);
    MessageFrame frame;
    ASSERT_EQ(asn1PD_MessageFrame(&ctxt, &frame), 0);
    ASSERT_EQ(frame.messageId, 20);
#if defined(_OBJASN1C_VERSION_760P_)
    BasicSafetyMessage *bsm = frame.value.u._MessageTypes_basicSafetyMessage;
    //    ASSERT_EQ(bsm->coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 확인할 수 없다.
    ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
    ASSERT_EQ(bsm->coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
    ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
    ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
    ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm->coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
    ASSERT_EQ(bsm->coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
    ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
    ASSERT_EQ(bsm->coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_x));
    ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_y));
    ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_z));
    ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].attitude.gyro_z));
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
    ASSERT_EQ(bsm->coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.abs_, kJ29451AntiLockBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
    ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
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
//    ASSERT_EQ(bsm.coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 확인할 수 없다.
    ASSERT_EQ(bsm.coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
    ASSERT_EQ(bsm.coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
    ASSERT_EQ(bsm.coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
    ASSERT_EQ(bsm.coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
    ASSERT_EQ(bsm.coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
    ASSERT_EQ(bsm.coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
    ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm.coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
    ASSERT_EQ(bsm.coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
    ASSERT_EQ(bsm.coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
    ASSERT_EQ(bsm.coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lat));
    ASSERT_EQ(bsm.coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lon));
    ASSERT_EQ(bsm.coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.vert));
    ASSERT_EQ(bsm.coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].accel.yaw));
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
    ASSERT_EQ(bsm.coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.albs, kJ29451AntiLockBrakeStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
    ASSERT_EQ(bsm.coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
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
//    ASSERT_EQ(bsm->coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 확인할 수 없다.
    ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
    ASSERT_EQ(bsm->coreData.Long, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
    ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
    ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
    ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm->coreData.speed, (int)j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
    ASSERT_EQ(bsm->coreData.heading, (int)j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
    ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
    // 가속도 값들은 butter-worth filter를 거치기 때문에 테스트입력값과 출력값이 다를 수 있다.
    // 따라서 가속도값들에 대한 비교는 생략한다 (가속도값들의 정확성은 J2945/1 드라이빙테스트를 통해 확인할 수 있다)
#if 0
    ASSERT_EQ(bsm->coreData.accelSet.Long, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_x));
    ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_y));
    ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_z));
    ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].attitude.gyro_z));
#endif
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 7) & 1, 1); // unavailable: set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 6) & 1, 0); // left front: not set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 5) & 1, 0); // left rear: not set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 4) & 1, 0); // right front: not set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 3) & 1, 0); // right rear: not set
    ASSERT_EQ(bsm->coreData.brakes.traction, (int)kJ29451TractionControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.albs, (int)kJ29451AntiLockBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.scs, (int)kJ29451StabilityControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.brakeBoost, (int)kJ29451BrakeBoostApplied_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.auxBrakes, (int)kJ29451AuxiliaryBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
    ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
    ASSERT_TRUE(bsm->partII_option);
    auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
    auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
    ASSERT_TRUE(exts != nullptr);
    ASSERT_FALSE(exts->events_option);
    // PH & PP의 내용의 확인은 생략한다.
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


/*
 * 입력된 GNSS 데이터가 다수의 BSM에 정상적으로 수납되는 것을 확인한다.
 */
TEST(CHECK_GNSS_DATA_IN_BSM, MULTIPLE_BSM)
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
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);

  unsigned int entry_num = 1;
  struct J29451Test_BSMTransmitCallbackListEntry *entry;

  /*
   * BSM 전송 시점마다 라이브러리에 최소필요 차량정보를 입력한다 (단위테스트에는 실제 gpsd 입력이 없으므로, 강제 입력한다)
   * Path history를 생성하기 위해 최소한 과거 3개의 GNSS 정보가 필요하므로, 4번째 GNSS 데이터가 확보된 이후에 첫번째 BSM이 송신된다.
   * 따라서 BSM 송신 횟수는 테스트 GNSS 데이터 개수에서 3을 뺀다.
   */
  for (unsigned int i = 0; i < TEST_GNSS_DATA_NUM - 3; i++) {
    while(g_bsm_callback_list.entry_num < entry_num); // BSM 송신시까지 대기
    g_j29451_mib.vehicle.size.width++; // 필수 차량정보 입력
    g_j29451_mib.vehicle.size.length++; // 필수 차량정보 입력
    entry_num++;
  }

  /*
   * BSM 송신 중지
   */
  J29451_StopBSMTransmit();

  /*
   * 결과 리스트에 저장된 모든 BSM 콜백함수 결과를 체크한다.
   * Path history를 생성하기 위해 최소한 과거 3개의 GNSS 정보가 필요하므로, 4번째 GNSS 데이터가 확보된 이후에 첫번째 BSM이 송신된다.
   * 따라서 테스트 GPS 데이터 중 3개는 제외한다
   */
  unsigned int init_msg_cnt;
  for (unsigned int i = 0; i < TEST_GNSS_DATA_NUM - 3; i++)
  {
    if (i == 0) {
      entry = TAILQ_FIRST(&(g_bsm_callback_list.head)); // 첫번째 BSM
      ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM
    } else {
      entry = TAILQ_NEXT(entry, entries); // 그 다음 BSM들
      ASSERT_FALSE(entry->cert_sign);
    }
    ASSERT_TRUE(entry != nullptr);
    ASSERT_FALSE(entry->id_change);
    ASSERT_FALSE(entry->event);

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
      init_msg_cnt = bsm->coreData.msgCnt; // 첫번째 BSM의 msgCnt는 랜덤값으로 설정된다.
    } else {
      ASSERT_EQ(bsm->coreData.msgCnt, (int)((init_msg_cnt + i) % 128)); /// msgCnt가 1씩 증가(wrap-around)하는지 확인
    }
    ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[i+3].fix.latitude));
    ASSERT_EQ(bsm->coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[i+3].fix.longitude));
    ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[i+3].fix.altHAE));
    ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[i+3].gst.smajor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[i+3].gst.sminor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[i+3].gst.smajor_orientation));
    ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm->coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[i+3].fix.speed));
    ASSERT_EQ(bsm->coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[i+3].fix.track));
    ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
    ASSERT_EQ(bsm->coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[i+3].attitude.acc_x));
    ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[i+3].attitude.acc_y));
    ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[i+3].attitude.acc_z));
    ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[i+3].attitude.gyro_z));
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
    ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
    ASSERT_EQ(bsm->coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.abs_, kJ29451AntiLockBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH + i);
    ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH + i);
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
      init_msg_cnt = bsm.coreData.msgCnt; // 첫번째 BSM의 msgCnt는 랜덤값으로 설정된다.
    } else {
      ASSERT_EQ(bsm.coreData.msgCnt, (int)((init_msg_cnt + i) % 128)); /// msgCnt가 1씩 증가(wrap-around)하는지 확인
    }
    ASSERT_EQ(bsm.coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[i+3].fix.latitude));
    ASSERT_EQ(bsm.coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[i+3].fix.longitude));
    ASSERT_EQ(bsm.coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[i+3].fix.altHAE));
    ASSERT_EQ(bsm.coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[i+3].gst.smajor_deviation));
    ASSERT_EQ(bsm.coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[i+3].gst.sminor_deviation));
    ASSERT_EQ(bsm.coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[i+3].gst.smajor_orientation));
    ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm.coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[i+3].fix.speed));
    ASSERT_EQ(bsm.coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[i+3].fix.track));
    ASSERT_EQ(bsm.coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
    ASSERT_EQ(bsm.coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[i+3].accel.lat));
    ASSERT_EQ(bsm.coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[i+3].accel.lon));
    ASSERT_EQ(bsm.coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[i+3].accel.vert));
    ASSERT_EQ(bsm.coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[i+3].accel.yaw));
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
    ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
    ASSERT_EQ(bsm.coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.albs, kJ29451AntiLockBrakeStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
    ASSERT_EQ(bsm.coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
    ASSERT_EQ(bsm.coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH + i);
    ASSERT_EQ(bsm.coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH + i);
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
    // BSM 디코딩 및 데이터 비교 - 강제로 설정한 GNSS 데이터가 맞게 수납되었는지 확인한다.
    j2735MessageFrame *msg = J29451_DecodeMessageFrame(entry->bsm, entry->bsm_size);
    ASSERT_TRUE(msg != nullptr);
    auto *bsm = (j2735BasicSafetyMessage *)(msg->value.u.data);
    if (i == 0) {
      init_msg_cnt = bsm->coreData.msgCnt; // 첫번째 BSM의 msgCnt는 랜덤값으로 설정된다.
    } else {
      ASSERT_EQ(bsm->coreData.msgCnt, (int)((init_msg_cnt + i) % 128)); /// msgCnt가 1씩 증가(wrap-around)하는지 확인
    }
    ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[i+3].fix.latitude));
    ASSERT_EQ(bsm->coreData.Long, j29451_ConvertGNSSLongitude(g_test_gps_data[i+3].fix.longitude));
    ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[i+3].fix.altHAE));
    ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[i+3].gst.smajor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[i+3].gst.sminor_deviation));
    ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[i+3].gst.smajor_orientation));
    ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);
    ASSERT_EQ(bsm->coreData.speed, (int)j29451_ConvertGNSSSpeed(g_test_gps_data[i+3].fix.speed));
    ASSERT_EQ(bsm->coreData.heading, (int)j29451_ConvertGNSSHeading(g_test_gps_data[i+3].fix.track));
    ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
    // 가속도 값들은 butter-worth filter를 거치기 때문에 테스트입력값과 출력값이 다를 수 있다.
    // 따라서 가속도값들에 대한 비교는 생략한다 (가속도값들의 정확성은 J2945/1 드라이빙테스트를 통해 확인할 수 있다)
#if 0
    ASSERT_EQ(bsm->coreData.accelSet.Long, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[i+3].attitude.acc_x));
    ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[i+3].attitude.acc_y));
    ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[i+3].attitude.acc_z));
    ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[i+3].attitude.gyro_z));
#endif
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 7) & 1, 1); // unavailable: set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 6) & 1, 0); // left front: not set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 5) & 1, 0); // left rear: not set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 4) & 1, 0); // right front: not set
    ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 3) & 1, 0); // right rear: not set
    ASSERT_EQ(bsm->coreData.brakes.traction, (int)kJ29451TractionControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.albs, (int)kJ29451AntiLockBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.scs, (int)kJ29451StabilityControlStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.brakeBoost, (int)kJ29451BrakeBoostApplied_Unavailable);
    ASSERT_EQ(bsm->coreData.brakes.auxBrakes, (int)kJ29451AuxiliaryBrakeStatus_Unavailable);
    ASSERT_EQ(bsm->coreData.size.width, (int)(TEST_VEHICLE_INFO_INITIAL_WIDTH + i));
    ASSERT_EQ(bsm->coreData.size.length, (int)(TEST_VEHICLE_INFO_INITIAL_LENGTH + i));
    ASSERT_TRUE(bsm->partII_option);
    auto *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
    auto *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
    ASSERT_TRUE(exts != nullptr);
    ASSERT_FALSE(exts->events_option);
    // PH & PP의 내용 확인은 생략한다
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


#if 0
/*
 * NAN 값을 갖는(=유효하지 않은) 필수 GNSS 데이터 입력 시, BSM이 전송되지 않는 것을 확인한다.
 * TODO:: 이 케이스는 PH와 함께 묶어서 테스트 필요.
 */
TEST(CHECK_GNSS_DATA_IN_BSM, NAN_GNSS_DATA)
{
  uint8_t addr[MAC_ALEN];
  memset(&g_bsm_callback_list, 0, sizeof(g_bsm_callback_list));
  TAILQ_INIT(&(g_bsm_callback_list.head));
  J29451Test_InitTestGPSData();
  ASSERT_EQ(J29451_Init(kJ29451LogLevel_Event, addr), kJ29451Result_Success);
  J29451_RegisterBSMTransmitCallback(J29451Test_ProcessBSMTransmitCallback);

  /*
   * BSM이 전송될 수 있도록 차량정보를 입력한다.
   */
  J29451_SetVehicleSize(TEST_VEHICLE_INFO_INITIAL_WIDTH, TEST_VEHICLE_INFO_INITIAL_LENGTH);

  /*
   * latitude가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].fix.latitude = NAN;
  ASSERT_EQ(J29451_StartBSMTransmit(kJ29451BSMTxInterval_Default), kJ29451Result_Success);
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * longitude가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].fix.longitude = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * speed가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].fix.speed = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * heading이 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].fix.track = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * altHAE가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].fix.altHAE = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * smajor_deviation이 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].gst.smajor_deviation = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * smajor_deviation이 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].gst.smajor_deviation = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * sminor_deviation이 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].gst.sminor_deviation = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * smajor_orientation이 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].gst.smajor_orientation = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * longitudinal acceleration이 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_j29451_mib.obu.gps_data.attitude.acc_x = NAN;
  g_j29451_mib.obu.gps_data.gst.smajor_orientation = g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * yawrate가 유효하지 않은 경우 BSM이 전송되지 않는 것을 확인한다. (전송주기의 3배를 기다려도 콜백함수가 호출되지 않는 것을 확인)
   */
  g_test_gps_data[g_test_gps_data_idx+1].attitude.gyro_z = NAN;
  usleep(g_j29451_mib.bsm_tx.tx_interval * 3 * 1000);
  ASSERT_EQ(g_bsm_callback_list.entry_num, 0U);

  /*
   * 모든 필수 GNSS 데이터가 유효해지면 BSM 전송이 시작되면서 콜백함수가 정상적으로 호출되는 것을 확인한다.
   */
  while(g_bsm_callback_list.entry_num == 0);
  struct J29451Test_BSMTransmitCallbackListEntry *entry = TAILQ_FIRST(&(g_bsm_callback_list.head));
  ASSERT_TRUE(entry != nullptr);
  ASSERT_FALSE(entry->id_change);
  ASSERT_FALSE(entry->event);
  ASSERT_TRUE(entry->cert_sign); // 라이브러리 초기화 후 첫번째 BSM

  /*
   * BSM 디코딩 및 데이터 비교 - 강제로 설정한 GPS 데이터가 맞게 수납되었는지 확인한다.
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
  //    ASSERT_EQ(bsm.coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 확인할 수 없다.
  ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
  ASSERT_EQ(bsm->coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
  ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
  ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
  ASSERT_EQ(bsm->coreData.transmission, kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm->coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  ASSERT_EQ(bsm->coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
  ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
  ASSERT_EQ(bsm->coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lat));
  ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lon));
  ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.vert));
  ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].accel.yaw));
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
  ASSERT_EQ((bsm->coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
  ASSERT_EQ(bsm->coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.abs_, kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
  ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
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
//    ASSERT_EQ(bsm.coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 확인할 수 없다.
  ASSERT_EQ(bsm.coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
  ASSERT_EQ(bsm.coreData.long_, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
  ASSERT_EQ(bsm.coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
  ASSERT_EQ(bsm.coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
  ASSERT_EQ(bsm.coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
  ASSERT_EQ(bsm.coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
  ASSERT_EQ(bsm.coreData.transmission, kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm.coreData.speed, j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  ASSERT_EQ(bsm.coreData.heading, j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
  ASSERT_EQ(bsm.coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
  ASSERT_EQ(bsm.coreData.accelSet.long_, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lat));
  ASSERT_EQ(bsm.coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.lon));
  ASSERT_EQ(bsm.coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].accel.vert));
  ASSERT_EQ(bsm.coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].accel.yaw));
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 7) & 1, 1); // unavailable: set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 6) & 1, 0); // left front: not set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 5) & 1, 0); // left rear: not set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 4) & 1, 0); // right front: not set
  ASSERT_EQ((bsm.coreData.brakes.wheelBrakes.data[0] >> 3) & 1, 0); // right rear: not set
  ASSERT_EQ(bsm.coreData.brakes.traction, kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.albs, kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.scs, kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.brakeBoost, kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(bsm.coreData.brakes.auxBrakes, kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(bsm.coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
  ASSERT_EQ(bsm.coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
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
//  ASSERT_EQ(bsm->coreData.msgCnt, 0); // 첫번째 BSM의 msgCnt는 랜덤값이 사용되므로 알 수 없다.
  ASSERT_EQ(bsm->coreData.lat, j29451_ConvertGNSSLatitude(g_test_gps_data[g_test_gps_data_idx].fix.latitude));
  ASSERT_EQ(bsm->coreData.Long, j29451_ConvertGNSSLongitude(g_test_gps_data[g_test_gps_data_idx].fix.longitude));
  ASSERT_EQ(bsm->coreData.elev, j29451_ConvertGNSSElevation(g_test_gps_data[g_test_gps_data_idx].fix.altHAE));
  ASSERT_EQ(bsm->coreData.accuracy.semiMajor, (int)j29451_ConvertGNSSSemiMajorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.smajor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.semiMinor, (int)j29451_ConvertGNSSSemiMinorAxisAccuracy(g_test_gps_data[g_test_gps_data_idx].gst.sminor_deviation));
  ASSERT_EQ(bsm->coreData.accuracy.orientation, (int)j29451_ConvertGNSSSemiMajorAxisOrientation(g_test_gps_data[g_test_gps_data_idx].gst.smajor_orientation));
  ASSERT_EQ(bsm->coreData.transmission, (int)kJ29451TransmissionState_Unavailable);
  ASSERT_EQ(bsm->coreData.speed, (int)j29451_ConvertGNSSSpeed(g_test_gps_data[g_test_gps_data_idx].fix.speed));
  ASSERT_EQ(bsm->coreData.heading, (int)j29451_ConvertGNSSHeading(g_test_gps_data[g_test_gps_data_idx].fix.track));
  ASSERT_EQ(bsm->coreData.angle, kJ29451SteeringWheelAngle_Unavailable);
  ASSERT_EQ(bsm->coreData.accelSet.Long, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_x));
  ASSERT_EQ(bsm->coreData.accelSet.lat, (int)j29451_ConvertGNSSAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_y));
  ASSERT_EQ(bsm->coreData.accelSet.vert, (int)j29451_ConvertGNSSVerticalAcceleration(g_test_gps_data[g_test_gps_data_idx].attitude.acc_z));
  ASSERT_EQ(bsm->coreData.accelSet.yaw, (int)j29451_ConvertGNSSYawRate(g_test_gps_data[g_test_gps_data_idx].attitude.gyro_z));
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 7) & 1, 1); // unavailable: set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 6) & 1, 0); // left front: not set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 5) & 1, 0); // left rear: not set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 4) & 1, 0); // right front: not set
  ASSERT_EQ((*(bsm->coreData.brakes.wheelBrakes.buf) >> 3) & 1, 0); // right rear: not set
  ASSERT_EQ(bsm->coreData.brakes.traction, (int)kJ29451TractionControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.albs, (int)kJ29451AntiLockBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.scs, (int)kJ29451StabilityControlStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.brakeBoost, (int)kJ29451BrakeBoostApplied_Unavailable);
  ASSERT_EQ(bsm->coreData.brakes.auxBrakes, (int)kJ29451AuxiliaryBrakeStatus_Unavailable);
  ASSERT_EQ(bsm->coreData.size.width, TEST_VEHICLE_INFO_INITIAL_WIDTH);
  ASSERT_EQ(bsm->coreData.size.length, TEST_VEHICLE_INFO_INITIAL_LENGTH);
  ASSERT_TRUE(bsm->partII_option);
  j2735PartIIcontent_1 *content = (j2735PartIIcontent_1 *)(bsm->partII.tab);
  j2735VehicleSafetyExtensions *exts = (j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);
  ASSERT_TRUE(exts != nullptr);
  ASSERT_FALSE(exts->events_option);
  // PH & PP의 내용 확인은 생략한다
  ASSERT_TRUE(exts->pathHistory_option); // per j2945/1
  ASSERT_FALSE(exts->pathHistory.initialPosition_option); // per j2945/1
  ASSERT_FALSE(exts->pathHistory.currGNSSstatus_option); // per j2945/1
  ASSERT_TRUE(exts->pathPrediction_option); // per j2945/1
  ASSERT_FALSE(exts->lights_option);
  J29451_FreeDecodedMessageFrame(msg);
#endif

  J29451Test_ReleaseEnv();
}
#endif