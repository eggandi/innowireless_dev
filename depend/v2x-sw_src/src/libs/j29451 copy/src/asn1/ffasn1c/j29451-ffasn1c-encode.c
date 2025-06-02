/** 
 * @file
 * @brief BSM 생성 관련 기능을 구현한 파일
 * @date 2020-10-03
 * @author gyun
 */


// 시스템 헤더 파일
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// 의존 라이브러리 헤더 파일
#include "ffasn1-j2735-2016.h"

// 라이브러리 내부 헤더 파일
#include "j29451-internal.h"
#include "j29451-internal-inline.h"


/**
 * @brief BSM CoreData 필드를 채운다.
 * @param[in] gnss 현 시점의 GNSS 데이터
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] core 정보를 채울 BSMCoreData 필드
 */
static void j29451_ffasn1c_FillBSMCoreData(
  struct J29451GNSSData *gnss,
  struct J29451VehicleInfo *vehicle,
  struct j2735BSMcoreData *core)
{
  Log(kJ29451LogLevel_Event, "Fill BsmCoreData\n");
  struct J29451BSMData *bsm_data = &(g_j29451_mib.bsm_data);
  core->msgCnt = (j2735MsgCount)(bsm_data->msg_cnt);
  bsm_data->msg_cnt = J29451_INCREASE_BSM_MSG_CNT(bsm_data->msg_cnt);
  core->id.len = J29451_TEMPORARY_ID_LEN;
  core->id.buf = asn1_mallocz(core->id.len);
  assert(core->id.buf);
  memcpy(core->id.buf, bsm_data->temporary_id, core->id.len);
  core->secMark = (j2735DSecond)(gnss->msec);
  core->lat = gnss->lat;
  core->Long = gnss->lon;
  core->elev = gnss->elev;
  core->speed = (j2735Speed)(gnss->speed);
  core->heading = (j2735Heading)(gnss->heading);
  core->accuracy.semiMajor = (j2735SemiMajorAxisAccuracy)(gnss->pos_accuracy.semi_major);
  core->accuracy.semiMinor = (j2735SemiMinorAxisAccuracy)(gnss->pos_accuracy.semi_minor);
  core->accuracy.orientation = (j2735SemiMajorAxisOrientation)(gnss->pos_accuracy.orientation);
  core->transmission = vehicle->transmission;
  core->angle = vehicle->angle;
  core->accelSet.lat = gnss->acceleration_set.lat;
  core->accelSet.Long = gnss->acceleration_set.lon;
  core->accelSet.vert = gnss->acceleration_set.vert;
  core->accelSet.yaw = gnss->acceleration_set.yaw;
  core->brakes.traction = vehicle->brakes.traction;
  core->brakes.albs = vehicle->brakes.abs;
  core->brakes.scs = vehicle->brakes.scs;
  core->brakes.brakeBoost = vehicle->brakes.brake_boost;
  core->brakes.auxBrakes = vehicle->brakes.aux_brakes;
  core->brakes.wheelBrakes.buf = asn1_mallocz(1);
  assert(core->brakes.wheelBrakes.buf);
  *(core->brakes.wheelBrakes.buf) = (vehicle->brakes.wheel_brakes.unavailable << 7) |
                                    (vehicle->brakes.wheel_brakes.left_front << 6) |
                                    (vehicle->brakes.wheel_brakes.left_rear << 5) |
                                    (vehicle->brakes.wheel_brakes.right_front << 4) |
                                    (vehicle->brakes.wheel_brakes.right_rear << 3);
  core->brakes.wheelBrakes.len = 5;
  core->size.length = (j2735VehicleLength)(vehicle->size.length);
  core->size.width = (j2735VehicleWidth)(vehicle->size.width);
}


/**
 * @brief Path history point 필드를 채운다.
 * @param[in] anchor 각 포인트들의 offset 값의 기준이 되는 기준 점 (=가장 최근의 GNSS 포인트)
 * @param[in] past Path history point 필드에 저장될 대상 포인트 정보
 * @param[out] point 정보를 채울 구조체 PathHistoryPoint 필드
 */
static inline void j29451_ffasn1c_FillPathHistoryPoint(
  struct J29451PathHistoryGNSSPointListEntry *anchor,
  struct J29451PathHistoryGNSSPointListEntry *past,
  struct j2735PathHistoryPoint *point)
{
  J29451LatLonOffsetLL_B18 lat_offset, lon_offset;
  J29451VertOffset_B12 elev_offset;
  J29451TimeOffset time_offset;
  lat_offset = j29451_CalculateLatOffset(anchor->point.lat, past->point.lat);
  lon_offset = j29451_CalculateLonOffset(anchor->point.lon, past->point.lon);
  elev_offset = j29451_CalculateElevOffset(anchor->point.elev, past->point.elev);
  time_offset = j29451_CalculateTimeOffset(anchor->point.time, past->point.time);
  point->latOffset = lat_offset;
  point->lonOffset = lon_offset;
  point->elevationOffset = elev_offset;
  point->timeOffset = (j2735TimeOffset)time_offset;
}


/**
 * @brief Path history 필드 내 crumbData 필드를 채운다.
 * @param[out] msg 값을 채울 crumbData 필드
 */
static inline void j29451_ffasn1c_FillPathHistoryPointList(j2735PathHistoryPointList *msg)
{
  struct J29451PathHistory *ph = &(g_j29451_mib.path.ph);
  struct J29451PathHistoryGNSSPointList *list = &(ph->gnss_point_list);
  assert(ph->ph_points.point_num >= kJ29451PathHistoryPointNum_Min);

  Log(kJ29451LogLevel_Event, "Fill PH point list - PH point cnt: %u\n", ph->ph_points.point_num);

  struct j2735PathHistoryPoint *asn1_point;
  struct J29451PathHistoryGNSSPointListEntry *anchor = TAILQ_LAST(&(list->head), J29451PathHistoryGNSSPointListEntryHead);
  assert(anchor);
  struct J29451PathHistoryGNSSPointListEntry *point = ph->ph_points.recent;
  assert(point);

  int point_cnt = (int)(ph->ph_points.point_num);
  msg->tab = asn1_mallocz(sizeof(struct j2735PathHistoryPoint) * point_cnt);
  assert(msg->tab);
  msg->count = point_cnt;
  for (int i = 0; i < point_cnt; i++) {
    assert(point);
    asn1_point = msg->tab + i;
    j29451_ffasn1c_FillPathHistoryPoint(anchor, point, asn1_point);
    point = point->ph_point.prev;
  }
  Log(kJ29451LogLevel_Event, "%d PH points are encapsulated\n", point_cnt);
}


/**
 * @brief Path history 필드를 채운다.
 * @param[out] msg 값을 채울 PathHistory 필드
 */
static void j29451_ffasn1c_FillPathHistory(struct j2735PathHistory *msg)
{
  /*
   * initial position 정보 및 currentGNSSStatus 정보는 채우지 않는다. (per SAE j2945/1)
   */
  msg->initialPosition_option = false;
  msg->currGNSSstatus_option = false;

  /*
   * PathHistoryPointList 정보를 채운다.
   */
  j29451_ffasn1c_FillPathHistoryPointList(&(msg->crumbData));
}


/**
 * @brief ExteriorLights 필드를 채운다.
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] ext ExteriorLights 필드
 * @return 설정된 비트가 있는지 여부
 */
static inline bool j29451_ffasn1c_FillExteriorLights(struct J29451VehicleInfo *vehicle, j2735ExteriorLights *msg)
{
  struct J29451ExteriorLights *lights = &(vehicle->lights);
  uint8_t flag1 = (lights->low_beam_headlight_on << 7) |
                  (lights->high_beam_headlight_on << 6) |
                  (lights->left_turn_signal_on << 5) |
                  (lights->right_turn_signal_on << 4) |
                  (lights->hazard_signal_on << 3) |
                  (lights->automatic_light_control_on << 2) |
                  (lights->daytime_running_lights_on << 1) |
                  (lights->fog_light_on << 0);
  uint8_t flag2 = lights->parking_light_on << 7;
  if (flag1 || flag2) {
    msg->buf = asn1_mallocz(2);
    if (msg->buf) {
      msg->len = 9;
      *(msg->buf) = flag1;
      *(msg->buf + 1) = flag2;
      return true;
    }
  }
  return false;
}


/**
 * @brief VehicleEventFlags 필드를 채운다. 이벤트 발생 상태가 아니면 해당 필드는 BSM에 수납되지 않는다.
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] msg 값을 채울 VehicleEventFlags 필드
 * @return 설정된 비트가 있는지 여부
 */
static inline int j29451_ffasn1c_FillVehicleEventFlags(struct J29451VehicleInfo *vehicle, j2735VehicleEventFlags *msg)
{
  uint8_t flag1 = (vehicle->event.event.hazard_lights << 7) |
                  (vehicle->event.event.stop_line_violation << 6) |
                  (vehicle->event.event.abs_activated << 5) |
                  (vehicle->event.event.traction_control_loss << 4) |
                  (vehicle->event.event.stability_control_activated << 3) |
                  (vehicle->event.event.hazardous_materials << 2) |
                  (vehicle->event.event.hard_braking << 0);
  uint8_t flag2 = (vehicle->event.event.lights_changed << 7) |
                  (vehicle->event.event.wiper_changed << 6) |
                  (vehicle->event.event.flat_tire << 5) |
                  (vehicle->event.event.disabled_vehicle << 4) |
                  (vehicle->event.event.airbag_deployment << 3);
  if (flag1 || flag2) {
    msg->buf = asn1_mallocz(2);
    if (msg->buf) {
      msg->len = 13;
      *(msg->buf) = flag1;
      *(msg->buf + 1) = flag2;
      return true;
    }
  }
  return false;
}


/**
 * @brief Path prediction 필드를 채운다.
 * @param[out] msg 값을 채울 path prediction 필드
 */
static inline void j29451_ffasn1c_FillPathPrediction(struct j2735PathPrediction *msg)
{
  struct J29451PathPrediction *pp = &(g_j29451_mib.path.pp);
  msg->radiusOfCurve = pp->radius_of_curve;
  msg->confidence = pp->confidence;
}


/**
 * @brief BSM Part2 VehicleSafetyExtensions 필드를 채운다.
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] content 정보를 채울 정보구조체 포인터
 */
static void
j29451_ffasn1c_FillVehicleSafetyExtensions(struct J29451VehicleInfo *vehicle, struct j2735PartIIcontent_1 *content)
{
  Log(kJ29451LogLevel_Event, "Fill BSM Part2 - VehicleSafetyExtensions\n");

  /*
   * 메모리를 할당한다.
   */
  content->partII_Id = 0; // = VehicleSafetyExtensions
  content->partII_Value.type = (ASN1CType *)asn1_type_j2735VehicleSafetyExtensions;
  content->partII_Value.u.data = asn1_mallocz_value(asn1_type_j2735VehicleSafetyExtensions);
  assert(content->partII_Value.u.data);

  struct j2735VehicleSafetyExtensions *ext = (struct j2735VehicleSafetyExtensions *)(content->partII_Value.u.data);

  /*
   * Path History 필드 정보를 채운다.
   */
  j29451_ffasn1c_FillPathHistory(&(ext->pathHistory));
  ext->pathHistory_option = true;

  /*
   * Path prediction 필드 정보를 채운다.
   */
  j29451_ffasn1c_FillPathPrediction(&(ext->pathPrediction));
  ext->pathPrediction_option = true;

  /*
   * (있을 경우) ExteriorLights 필드 정보를 채운다.
   */
  if (j29451_ffasn1c_FillExteriorLights(vehicle, &(ext->lights)) == true) {
    ext->lights_option = true;
  }

  /*
   * (있을 경우) VehicleEventFlag 필드 정보를 채운다.
   */
  if (j29451_ffasn1c_FillVehicleEventFlags(vehicle, &(ext->events)) == true) {
    ext->events_option = true;
  }
}


/**
 * @brief BSM part2 필드의 정보를 채운다.
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] part2 정보를 채울 정보구조체 포인터
 */
static void j29451_ffasn1c_FillBSMPart2(struct J29451VehicleInfo *vehicle, struct j2735BasicSafetyMessage_1 *part2)
{
  Log(kJ29451LogLevel_Event, "Fill BSM Part2\n");

  /*
   * VehicleSafetyExtensions 확장 영역을 위한 메모리를 할당
   */
  part2->count = 1;
  part2->tab = asn1_mallocz_value(asn1_type_j2735PartIIcontent_1);
  assert(part2->tab);
  j29451_ffasn1c_FillVehicleSafetyExtensions(vehicle, (struct j2735PartIIcontent_1 *)(part2->tab));
}


/**
 * @brief BSM 정보를 채운다.
 * @param[in] gnss 현 시점의 GNSS 데이터
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] bsm 정보를 채울 BSM 정보구조체
 */
static void j29451_ffasn1c_FillBSM(
  struct J29451GNSSData *gnss,
  struct J29451VehicleInfo *vehicle,
  struct j2735BasicSafetyMessage *bsm)
{
  Log(kJ29451LogLevel_Event, "Fill BSM\n");

  /*
   * BsmCoreData 및 Part2 필드를 채운다.
   */
  j29451_ffasn1c_FillBSMCoreData(gnss, vehicle, &(bsm->coreData));
  bsm->partII_option = true;
  j29451_ffasn1c_FillBSMPart2(vehicle, &(bsm->partII));
}


#if 0 // NOTE:: 디버깅 시에만 사용
/**
 * @brief 채워진 MessageFrame asn.1 구조체의 내용을 출력한다.
 * @param[in] log 출력로그레벨
 * @param[in] frame 출력할 MessageFrame
 */
static void j29451_ffasn1c_PrintMessageFrame(J29451LogLevel log, j2735MessageFrame *frame)
{
  if (g_j29451_log >= log) {
    Log(log, "Frame - messagId: %d\n", frame->messageId);
    struct j2735BasicSafetyMessage *bsm = frame->value.u.data;
    if (bsm == NULL) { Log(log, "Null BSM\n"); return; }
    Log(log, "BSM.coreData\n");
    if (bsm->coreData.id.len != 4) { Log(log, "Invalid temporaryID len\n"); return; }
    if (bsm->coreData.id.buf == NULL) { Log(log, "Null temporaryID\n"); return; }
    Log(log, "  msgCnt: %d, id: 0x%02X%02X%02X%02X, secMark: %d, lat: %d, lon: %d, elev: %d\n",
        bsm->coreData.msgCnt, bsm->coreData.id.buf[0], bsm->coreData.id.buf[1], bsm->coreData.id.buf[2],
        bsm->coreData.id.buf[3], bsm->coreData.secMark, bsm->coreData.lat,
        bsm->coreData.Long, bsm->coreData.elev);
    Log(log, "  accuracy - smajor: %d, sminor: %d, orientation; %d\n",
        bsm->coreData.accuracy.semiMajor, bsm->coreData.accuracy.semiMinor, bsm->coreData.accuracy.orientation);
    Log(log, "  trans: %d, speed: %d, heading: %d, angle: %d\n",
        bsm->coreData.transmission, bsm->coreData.speed, bsm->coreData.heading, bsm->coreData.angle);
    Log(log, "  accelSet - lon: %d, lat: %d, vert: %d, yaw: %d\n",
        bsm->coreData.accelSet.Long, bsm->coreData.accelSet.lat, bsm->coreData.accelSet.vert, bsm->coreData.accelSet.yaw);
    Log(log, "  brakes -  wheel.bitLen: %d, traction: %d, albs: %d, scs: %d, brakeBoost: %d, aux: %d\n",
        bsm->coreData.brakes.wheelBrakes.len, bsm->coreData.brakes.traction, bsm->coreData.brakes.albs, bsm->coreData.brakes.scs, bsm->coreData.brakes.brakeBoost,
        bsm->coreData.brakes.auxBrakes);
    if (bsm->coreData.brakes.wheelBrakes.buf == NULL) { Log(log, "Null wheelBrakes\n"); return; }
    Log(log, "  size - width: %d, length: %d\n", bsm->coreData.size.width, bsm->coreData.size.length);
    if (bsm->partII_option == false) { Log(log, "Error - No PartII\n"); return; }
    Log(log, "PartII count: %d\n", bsm->partII.count);
    if (bsm->partII.count != 1) { Log(log, "Invalid PartII count\n"); return; }
    j2735PartIIcontent_1 *part2 = bsm->partII.tab;
    if (part2 == NULL) { Log(log, "Null partIIContent\n"); return; }
    Log(log, "PartII id: %d\n", part2->partII_Id);
    if (part2->partII_Id != 0) { Log(log, "Invalid PartII id\n"); return; }
    struct j2735VehicleSafetyExtensions *ext = (struct j2735VehicleSafetyExtensions *)(part2->partII_Value.u.data);
    if (ext == NULL) { Log(log, "Error - Null VehicleSafetyExtension\n"); return; }
    Log(log, "VehicleSafetyExtension\n");
    if (ext->events_option) {
      Log(log, "  Event.bitLen: %d\n", ext->events.len);
      if (ext->events.buf == NULL) { Log(log, "Error - Null Event bitstring\n"); return; }
    }
    if (ext->pathHistory_option == false) { Log(log, "No PH\n"); return; }
    if (ext->pathHistory.initialPosition_option == true) { Log(log, "initialPosition presents\n"); return; }
    if (ext->pathHistory.currGNSSstatus_option == true) { Log(log, "currGNSSstatus presents\n"); return; }
    Log(log, "  crumbData.count: %d\n", ext->pathHistory.crumbData.count);
    if (ext->pathHistory.crumbData.tab == NULL) { Log(log, "Null crumbData\n"); return; }
    if ((ext->pathHistory.crumbData.count < 1) || (ext->pathHistory.crumbData.count > 23)) { Log(log, "invalid crumbData count\n"); return; }
    for (size_t i = 0; i < ext->pathHistory.crumbData.count; i++) {
      j2735PathHistoryPoint *pt = ext->pathHistory.crumbData.tab + i;
      Log(log, "  crumbData[%u] lat: %d, lon: %d, elev: %d, time: %d\n",
          i, pt->latOffset, pt->lonOffset, pt->elevationOffset, pt->timeOffset);
      if (pt->speed_option) { Log(log, "             speed present\n"); return; }
      if (pt->posAccuracy_option) { Log(log, "             posAccuracy present\n"); return; }
      if (pt->heading_option) { Log(log, "             heading present\n"); return; }
    }
  }
}
#endif


/**
 * @brief BSM을 생성한다.
 * @param[in] gnss 현 시점의 GNSS 데이터
 * @param[in] vehicle 현 시점의 차량정보
 * @param[out] bsm_size 생성된 BSM의 길이가 반환될 변수 포인터
 * @return 생성된 BSM 바이트열 (호출자는 사용 후 free() 해 주어야 한다)
 * @retval NULL: 생성 실패
 */
uint8_t INTERNAL *
j29451_ffasn1c_ConstructBSM(struct J29451GNSSData *gnss, struct J29451VehicleInfo *vehicle, size_t *bsm_size)
{
  Log(kJ29451LogLevel_Event, "Construct BSM\n");

  uint8_t *buf = NULL;
  struct j2735MessageFrame *frame = NULL;
  struct j2735BasicSafetyMessage *bsm = NULL;

  /*
   * 인코딩을 위한 asn.1 정보구조체를 할당하고 초기화한다.
   */
  frame = (struct j2735MessageFrame *)asn1_mallocz_value(asn1_type_j2735MessageFrame);
  bsm = (struct j2735BasicSafetyMessage *)asn1_mallocz_value(asn1_type_j2735BasicSafetyMessage);
  assert(frame);
  assert(bsm);
  frame->messageId = 20; // BasicSafetyMessage
  frame->value.type = (ASN1CType *)asn1_type_j2735BasicSafetyMessage;
  frame->value.u.data = bsm;

  /*
   * BSM 메시지에 정보를 채운다.
   */
  j29451_ffasn1c_FillBSM(gnss, vehicle, bsm);

  /*
   * 인코딩한다.
   */
  *bsm_size = (size_t)asn1_uper_encode(&buf, asn1_type_j2735MessageFrame, frame);
  if (buf == NULL) {
    Err("Fail to construct BSM - asn1_uper_encode() failed\n");
#if 0 // NOTE:: 디버깅 시에만 사용
    j29451_ffasn1c_PrintMessageFrame(kJ29451LogLevel_Err, frame);
#endif
    goto out;
  }
  Log(kJ29451LogLevel_Event, "Success to construct %u-bytes BSM\n", *bsm_size);

out:
  asn1_free_value(asn1_type_j2735MessageFrame, frame);
  return buf;
}
