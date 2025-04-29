#include "relay_v2x_j2735_bsm.h"
#include "relay_config.h"

extern struct relay_inno_gnss_data_t *G_gnss_data;
extern struct relay_inno_gnss_data_bsm_t *G_gnss_bsm_data;

static struct j2735BSMcoreData *g_core; 
static bool g_bsm_core_data_installed = false; 

static uint8_t g_msg_bsm_tx_cnt = 0; 
static uint8_t g_temporary_id[RELAY_INNO_TEMPORARY_ID_LEN] = { 0x00, 0x01, 0x02, 0x03 }; 
static int g_transmission = 7; // neutral
static int g_angle = 127; 
static int g_traction = 0; // unavailable
static int g_abs = 0; // off
static int g_scs = 0; // on
static int g_brake_boost = 0; // on
static int g_aux_brakes = 0; // on
static int g_wheel_brakes_unavailable = 1; // true
static int g_wheel_brakes_left_front = 0; // false
static int g_wheel_brakes_left_rear = 0; // true
static int g_wheel_brakes_right_front = 0; // false
static int g_wheel_brakes_right_rear = 0; // true
static int g_vehicle_length = 1000; 
static int g_vehicle_width = 1001; 

#define RELAY_INNO_MAX_PATHHISTORYPOINT 23
struct relay_inno_PathHistoryPointList_t
{
	j2735PathHistoryPoint tab[RELAY_INNO_MAX_PATHHISTORYPOINT];
  size_t count;
};
static struct relay_inno_PathHistoryPointList_t g_pathhistorypointlistlist = {.count = 0};

static int RELAY_INNO_BSM_SecMark(); 
static int RELAY_INNO_BSM_Fill_CoreData(struct j2735BSMcoreData *core_ptr); 
static int RELAY_INNO_BSM_Fill_PartII(struct j2735PartIIcontent_1 *partII_ptr);
static size_t RELAY_INNO_BSM_Push_Pathhistroty();
static size_t RELAY_INNO_BSM_Move_Pathhistroty();


/** 
 * @brief BSM을 생성한다.([j2736 Frame[BSM Data]])
 * @param[out] bsm_size BSM 크기
 * @retval BSM 인코딩정보 포인터
*/
EXTERN_API uint8_t *REPLAY_INNO_J2736_Construct_BSM(size_t *bsm_size)
{
	uint8_t *buf = NULL;
  struct j2735MessageFrame *frame = NULL;
  struct j2735BasicSafetyMessage *bsm = NULL;

	if (((frame = (struct j2735MessageFrame *)asn1_mallocz_value(asn1_type_j2735MessageFrame)) == NULL) ||
      ((bsm = (struct j2735BasicSafetyMessage *)asn1_mallocz_value(asn1_type_j2735BasicSafetyMessage)) == NULL)) {
    printf("Fail to encode BSM - asn1_mallocz_value() failed\n");
    goto out;
  }
	
	if(RELAY_INNO_J2735_Fill_BSM(bsm) < 0)
	{
		return NULL;
	}
#if 0
	_DEBUG_PRINT("G_gnss_data->status.is_healthy:%d\n", G_gnss_data->status.is_healthy);
	_DEBUG_PRINT("G_gnss_data->status.unavailable:%d\n", G_gnss_data->status.unavailable);
	_DEBUG_PRINT("bsm->coreData.msgCnt: %d\n", bsm->coreData.msgCnt);
	_DEBUG_PRINT("bsm->coreData.secMark: %d\n", bsm->coreData.secMark);	
	_DEBUG_PRINT("bsm->coreData.id: %02X %02X %02X %02X\n", bsm->coreData.id.buf[0], bsm->coreData.id.buf[1], bsm->coreData.id.buf[2], bsm->coreData.id.buf[3]);
	_DEBUG_PRINT("bsm->coreData.lat: %d\n", bsm->coreData.lat);
	_DEBUG_PRINT("bsm->coreData.Long: %d\n", bsm->coreData.Long);
	_DEBUG_PRINT("bsm->coreData.elev: %d\n", bsm->coreData.elev);
	_DEBUG_PRINT("bsm->coreData.accuracy.semiMajor: %d\n", bsm->coreData.accuracy.semiMajor);
	_DEBUG_PRINT("bsm->coreData.accuracy.semiMinor: %d\n", bsm->coreData.accuracy.semiMinor);
	_DEBUG_PRINT("bsm->coreData.accuracy.orientation: %d\n", bsm->coreData.accuracy.orientation);
	_DEBUG_PRINT("bsm->coreData.transmission: %d\n", bsm->coreData.transmission);
	_DEBUG_PRINT("bsm->coreData.speed: %d\n", bsm->coreData.speed);
	_DEBUG_PRINT("bsm->coreData.heading: %d\n", bsm->coreData.heading);
	_DEBUG_PRINT("bsm->coreData.angle: %d\n", bsm->coreData.angle);
	_DEBUG_PRINT("bsm->coreData.accelSet.lat: %d\n", bsm->coreData.accelSet.lat);
	_DEBUG_PRINT("bsm->coreData.accelSet.Long: %d\n", bsm->coreData.accelSet.Long);
	_DEBUG_PRINT("bsm->coreData.accelSet.vert: %d\n", bsm->coreData.accelSet.vert);
	_DEBUG_PRINT("bsm->coreData.accelSet.yaw: %d\n", bsm->coreData.accelSet.yaw);
	_DEBUG_PRINT("bsm->coreData.size.length: %d\n", bsm->coreData.size.length);
	_DEBUG_PRINT("bsm->coreData.size.width: %d\n", bsm->coreData.size.width);
#endif
  frame->messageId = 20; // BasicSafetyMessage (per SAE j2735)
  frame->value.type = (ASN1CType *)asn1_type_j2735BasicSafetyMessage;
  frame->value.u.data = bsm;

  // BSM을 인코딩한다.
  *bsm_size = (size_t)asn1_uper_encode(&buf, asn1_type_j2735MessageFrame, frame);
  if (buf == NULL) {
    _DEBUG_PRINT("Fail to encode BSM - asn1_uper_encode() failed\n");
    goto out;
  }else{
		if(1)
		{
			g_pathhistorypointlistlist.count = RELAY_INNO_BSM_Push_Pathhistroty();	
		}
		
		g_msg_bsm_tx_cnt = (g_msg_bsm_tx_cnt + 1) % 128;
	}
out:
  if(frame) 
	{ 
		asn1_free_value(asn1_type_j2735MessageFrame, frame); 
	}
	
  return buf;
}
/**
 * @brief BSM 인코딩정보에 값을 채운다.
 * @param[out] bsm 정보를 채울 BSM 인코딩정보 구조체 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 */
EXTERN_API int RELAY_INNO_J2735_Fill_BSM(struct j2735BasicSafetyMessage *bsm)
{
	int ret;

	if(g_bsm_core_data_installed == false)
	{
		struct j2735BSMcoreData *core = NULL;
		ret = RELAY_INNO_BSM_Gnss_Info_Ptr_Instrall(&core);
		if(ret < 0)
		{
			_DEBUG_PRINT("Fail to install BSM core data\n");
			return ret;
		}else{
			printf("BSM core data installed\n");
			return -1;
		}
	}

	ret = RELAY_INNO_BSM_Fill_CoreData(&bsm->coreData);
	if(ret < 0)
	{
		_DEBUG_PRINT("Fail to fill BSM core data\n");
		return ret;
	}
	bsm->partII_option = true;
	if(bsm->partII_option == true)
	{
		bsm->partII.count = 3;
		bsm->partII.tab = asn1_mallocz(asn1_get_size(asn1_type_j2735PartIIcontent_1) * bsm->partII.count);
		for(size_t count_num = 0; count_num < bsm->partII.count; count_num++)
		{
			struct j2735PartIIcontent_1 *tab_now = bsm->partII.tab + count_num;
			if(tab_now != NULL)
			{
				tab_now->partII_Id = count_num;
				ret = RELAY_INNO_BSM_Fill_PartII(tab_now);
			}
		}
	}

	bsm->regional_option = true;
	if(bsm->regional_option == true)
	{
		bsm->regional.count = 1;
		bsm->regional.tab = asn1_mallocz(asn1_get_size(asn1_type_j2735RegionalExtension_1) * bsm->regional.count);
		for(size_t count_num = 0; count_num < bsm->regional.count; count_num++)
		{
  		j2735RegionalExtension_1 *tab_now = bsm->regional.tab + count_num;
			if(tab_now != NULL)
			{
				tab_now->regionId = 4;
				tab_now->regExtValue.type = NULL;
				tab_now->regExtValue.u.octet_string.len = 6;
				tab_now->regExtValue.u.octet_string.buf = asn1_mallocz(tab_now->regExtValue.u.octet_string.len);
				if(tab_now->regExtValue.u.octet_string.buf == NULL)
				{
					return -1;
				}
				memcpy(tab_now->regExtValue.u.octet_string.buf, (uint8_t []){0x1C, 0x00, 0x00, 0x00, 0x00, 0x00}, tab_now->regExtValue.u.octet_string.len);	
			}

			
		}
	}
	return 0;
}

/**
 * @brief BSM Core 데이터 중 Gnss관련 정보를 포인터로 연결한다.
 * @param[in] core BSM Core 데이터 주소 포인터
 * @retval void
 * @note BSM Core 데이터의 포인터를 전달하지 않으면 내부적으로 생성된 구조체를 사용한다.
 */
EXTERN_API int RELAY_INNO_BSM_Gnss_Info_Ptr_Instrall(struct j2735BSMcoreData **core_ptr)
{
	struct j2735BSMcoreData *core;
	if(*core_ptr == NULL)
	{
		g_core = malloc(sizeof(struct j2735BSMcoreData));
		memset(g_core, 0, sizeof(struct j2735BSMcoreData));
	}else{
		
		g_core = *core_ptr;
	}
	core = g_core;	
	G_gnss_bsm_data = malloc(sizeof(struct relay_inno_gnss_data_bsm_t));
	memset(G_gnss_bsm_data, 0, sizeof(struct relay_inno_gnss_data_bsm_t));
	if(G_gnss_bsm_data == NULL)
	{
		return -1;
	}

	G_gnss_bsm_data->lat = (int*)&core->lat;
	G_gnss_bsm_data->lon = (int*)&core->Long;
	G_gnss_bsm_data->elev = (int*)&core->elev;
	G_gnss_bsm_data->speed = (uint32_t*)&core->speed;
	G_gnss_bsm_data->heading = (uint32_t*)&core->heading;
	G_gnss_bsm_data->acceleration_set.lat = (int*)&core->accelSet.lat;
	G_gnss_bsm_data->acceleration_set.lon = (int*)&core->accelSet.Long;
	G_gnss_bsm_data->acceleration_set.vert = (int*)&core->accelSet.vert;
	G_gnss_bsm_data->acceleration_set.yaw = (int*)&core->accelSet.yaw;
	G_gnss_bsm_data->pos_accuracy.semi_major = (unsigned int*)&core->accuracy.semiMajor;
	G_gnss_bsm_data->pos_accuracy.semi_minor = (unsigned int*)&core->accuracy.semiMinor;
	G_gnss_bsm_data->pos_accuracy.orientation = (unsigned int*)&core->accuracy.orientation;

	G_gnss_bsm_data->isused = true;
	g_bsm_core_data_installed = true;
	return 0;
}

/**
 * @brief BSMCoreData 인코딩정보에 값을 채운다.
 * @param[out] core 값을 채울 BSMCoreData 인코딩정보 구조체 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 */
static int RELAY_INNO_BSM_Fill_CoreData(struct j2735BSMcoreData *core_ptr)
{
  int ret = -1;
	struct j2735BSMcoreData *core = core_ptr;
	if(G_gnss_bsm_data->isused == true)
	{
		if(g_core != NULL)
		{
			asn1_copy_value(asn1_type_j2735BSMcoreData, core, g_core);
		}
	}
  if(G_gnss_data->status.unavailable == FALSE || G_relay_inno_config.v2x.j2735.bsm.tx_forced == true) 	
  {
    core->msgCnt = RELAY_INNO_INCREASE_BSM_MSG_CNT(g_msg_bsm_tx_cnt);
    core->id.len = RELAY_INNO_TEMPORARY_ID_LEN;
		if(core->id.buf == NULL){
    	core->id.buf = asn1_mallocz(core->id.len);
		}else{
			memset(core->id.buf, 0, core->id.len);
		}
    if (core->id.buf) {
      memcpy(core->id.buf, g_temporary_id, RELAY_INNO_TEMPORARY_ID_LEN);
		}
		core->secMark = RELAY_INNO_BSM_SecMark();
		g_core->secMark = core->secMark;
		core->transmission = g_transmission;
		core->angle = g_angle;
		core->brakes.traction = g_traction;
		core->brakes.albs = g_abs;
		core->brakes.scs = g_scs;
		core->brakes.brakeBoost = g_brake_boost;
		core->brakes.auxBrakes = g_aux_brakes;
		if(core->brakes.wheelBrakes.buf == NULL)
		{
			core->brakes.wheelBrakes.buf = asn1_mallocz(1);
		}else{
			memset(core->brakes.wheelBrakes.buf, 0, 1);
		}
		if (core->brakes.wheelBrakes.buf) 
		{
			*(core->brakes.wheelBrakes.buf) = (g_wheel_brakes_unavailable << 7) |
																				(g_wheel_brakes_left_front << 6) |
																				(g_wheel_brakes_left_rear << 5) |
																				(g_wheel_brakes_right_front << 4) |
																				(g_wheel_brakes_right_rear << 3);
			core->brakes.wheelBrakes.len = 5;
		}
		core->size.length = g_vehicle_length;
		core->size.width = g_vehicle_width;
		ret = 0;
  }

  return ret;
}



/**
 * @brief BSM Part II를 채운다.
 * @param[out] partII_ptr 값을 채울 BSM Part II 인코딩정보 구조체 포인터
 * @retval 0: 성공
 */
static int RELAY_INNO_BSM_Fill_PartII(struct j2735PartIIcontent_1 *partII_ptr)
{
	switch(partII_ptr->partII_Id)
	{
		case 0: // VehicleSafetyExtensions
		{
			partII_ptr->partII_Value.type = (ASN1CType *)asn1_type_j2735VehicleSafetyExtensions;
			partII_ptr->partII_Value.u.data = asn1_mallocz_value(asn1_type_j2735VehicleSafetyExtensions);
			struct j2735VehicleSafetyExtensions *data_ptr = partII_ptr->partII_Value.u.data;
			if(g_pathhistorypointlistlist.count > 0)
			{
				data_ptr->pathHistory_option = true;
				if(data_ptr->pathHistory_option == true)
				{
					memset(&data_ptr->pathHistory, 0x00, sizeof(struct j2735PathHistory));
					data_ptr->pathHistory.crumbData.count = g_pathhistorypointlistlist.count;
					data_ptr->pathHistory.crumbData.tab = asn1_mallocz(asn1_get_size(asn1_type_j2735PathHistoryPoint) * data_ptr->pathHistory.crumbData.count);
					for(size_t count_num = 0; count_num < g_pathhistorypointlistlist.count; count_num++)
					{
						j2735PathHistoryPoint *pathhistorypoint = &g_pathhistorypointlistlist.tab[count_num];
						j2735PathHistoryPoint *pathhistorypoint_ptr = data_ptr->pathHistory.crumbData.tab + count_num;
						asn1_copy_value(asn1_type_j2735PathHistoryPoint, pathhistorypoint_ptr, pathhistorypoint);
						pathhistorypoint_ptr->latOffset = g_core->lat - pathhistorypoint->latOffset;
						pathhistorypoint_ptr->lonOffset = g_core->Long - pathhistorypoint->lonOffset;
						pathhistorypoint_ptr->elevationOffset = g_core->elev - pathhistorypoint->elevationOffset;
						pathhistorypoint_ptr->timeOffset = g_core->secMark - pathhistorypoint->timeOffset;
						if(pathhistorypoint_ptr->timeOffset < 0)
						{
							pathhistorypoint_ptr->timeOffset += 65535;
						}
						#if 0
						printf("count_num: %ld\n", count_num);
						printf("latOffset: %d - %d = %d\n", g_core->lat, pathhistorypoint->latOffset, pathhistorypoint_ptr->latOffset);
						printf("lonOffset: %d - %d = %d\n", g_core->Long, pathhistorypoint->lonOffset, pathhistorypoint_ptr->lonOffset);
						printf("elevationOffset: %d - %d = %d\n", g_core->elev, pathhistorypoint->elevationOffset, pathhistorypoint_ptr->elevationOffset);
						printf("timeOffset: %d - %d = %d\n", g_core->secMark, pathhistorypoint->timeOffset, pathhistorypoint_ptr->timeOffset);
						#endif
					}
					
				}
			}
			if(data_ptr->pathPrediction_option == true)
			{
				data_ptr->pathPrediction.radiusOfCurve = 32767; // straight path
				data_ptr->pathPrediction.confidence = 4095; // unavailable
			}
			break;
		}
		case 1: // SpecialVehicleExtensions
		{
			partII_ptr->partII_Value.type = (ASN1CType *)asn1_type_j2735SpecialVehicleExtensions;
			partII_ptr->partII_Value.u.data = asn1_mallocz_value(asn1_type_j2735SpecialVehicleExtensions);
			struct j2735SpecialVehicleExtensions *data_ptr = partII_ptr->partII_Value.u.data;
			data_ptr->description_option = true; // unavailable
			memset(&data_ptr->description, 0x00, sizeof(struct j2735EventDescription));
			data_ptr->description.typeEvent = 0; // ITIScodes
			data_ptr->trailers_option = false;
			break;
		}
		case 2: // SupplementalVehicleExtensions
		{
			partII_ptr->partII_Value.type = (ASN1CType *)asn1_type_j2735SupplementalVehicleExtensions;
			partII_ptr->partII_Value.u.data = asn1_mallocz_value(asn1_type_j2735SupplementalVehicleExtensions);
			struct j2735SupplementalVehicleExtensions *data_ptr = partII_ptr->partII_Value.u.data;
			data_ptr->classDetails_option = true; // unavailable
			memset(&data_ptr->classDetails, 0x00, sizeof(struct j2735VehicleClassification));
			data_ptr->classDetails.role_option = true;
			data_ptr->classDetails.role = j2735BasicVehicleRole_basicVehicle;
			data_ptr->classDetails.vehicleType_option = true; 
			data_ptr->classDetails.vehicleType = j2735VehicleGroupAffected_cars;
			break;
		}
	}
	return 0;
}

/**
 * @brief PathHistoryPoint를 이동한다.
 * @retval PathHistoryPoint 개수(디버깅용)
 */
static size_t RELAY_INNO_BSM_Move_Pathhistroty()
{
	if(g_pathhistorypointlistlist.count == RELAY_INNO_MAX_PATHHISTORYPOINT)
	{
		// PathHistoryPoint의 개수가 최대 개수에 도달했을 경우, 가장 오래된 PathHistoryPoint를 삭제한다.
		g_pathhistorypointlistlist.count--;
		memset(&g_pathhistorypointlistlist.tab[g_pathhistorypointlistlist.count], 0x00, sizeof(j2735PathHistoryPoint));
		// PathHistoryPoint 개수가 0이면 PathHistoryPoint를 이동할 필요가 없으므로 return 한다.
		if(g_pathhistorypointlistlist.count == 0)
		{
			return 0;
		}
	}
	// PathHistoryPoint를 이동한다.
	for(size_t count_num = g_pathhistorypointlistlist.count; 0 < count_num; count_num--)
	{
		memcpy(&g_pathhistorypointlistlist.tab[count_num], &g_pathhistorypointlistlist.tab[count_num - 1] , sizeof(j2735PathHistoryPoint));
	}
	memset(&g_pathhistorypointlistlist.tab[0], 0x00, sizeof(j2735PathHistoryPoint));
	return g_pathhistorypointlistlist.count;
}

/**
 * @brief PathHistoryPoint를 추가한다.
 * @retval PathHistoryPoint 개수
 */
static size_t RELAY_INNO_BSM_Push_Pathhistroty()
{
	RELAY_INNO_BSM_Move_Pathhistroty();
	j2735PathHistoryPoint *pathhistorypoint = &g_pathhistorypointlistlist.tab[0];
	pathhistorypoint->latOffset = g_core->lat; // unavailable
	pathhistorypoint->lonOffset = g_core->Long; // unavailable
	pathhistorypoint->elevationOffset = g_core->elev; // unavailable
	pathhistorypoint->timeOffset = g_core->secMark;
	#if 0
	if(0 < *G_gnss_bsm_data->speed && *G_gnss_bsm_data->speed < 8191)
	{
		pathhistorypoint->speed_option = true;
		pathhistorypoint->speed = (j2735Speed)*G_gnss_bsm_data->speed; // Units of 0.02 m/s
	}else{
		pathhistorypoint->speed_option = false;
		pathhistorypoint->speed = 8191;//(j2735Speed)*G_gnss_bsm_data->speed; // Units of 0.02 m/s
	}
	pathhistorypoint->posAccuracy_option = false;
	if(0 < *G_gnss_bsm_data->heading && *G_gnss_bsm_data->heading < 240)
	{
		pathhistorypoint->heading_option = true;
		pathhistorypoint->heading = (j2735Heading)*G_gnss_bsm_data->heading; // Units of 0.1 degrees
	}else{
		pathhistorypoint->heading_option = false;
		pathhistorypoint->heading = 0;//(j2735Heading)*G_gnss_bsm_data->heading; // Units of 0.1 degrees
	}
	#else
	pathhistorypoint->speed_option = false;
	pathhistorypoint->heading_option = false;

	#endif

	_DEBUG_PRINT("pathhistorypoint->speed_option:%d\n", pathhistorypoint->speed_option);
	_DEBUG_PRINT("pathhistorypoint->speed:%d\n", pathhistorypoint->speed);
	_DEBUG_PRINT("G_gnss_bsm_data->speed:%d\n", *G_gnss_bsm_data->speed);

	_DEBUG_PRINT("pathhistorypoint->heading_option:%d\n", pathhistorypoint->heading_option);
	_DEBUG_PRINT("pathhistorypoint->heading:%d\n", pathhistorypoint->heading);
	_DEBUG_PRINT("G_gnss_bsm_data->heading:%d\n", *G_gnss_bsm_data->heading);

	g_pathhistorypointlistlist.count++;
	return g_pathhistorypointlistlist.count;
}


/**
 * @brief BSM 메시지 카운트를 증가시킨다.
 * @param[in] msg_cnt BSM 메시지 카운트
 * @retval BSM 메시지 카운트
 */
static int RELAY_INNO_BSM_SecMark()
{
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME, &tv); 
	struct tm *tm;
	tm = localtime(&tv.tv_sec);
	int ret = 0;
	ret += tm->tm_sec * 1000;
	ret += (int)((tv.tv_nsec)/1000000);
	
	return ret % 65535;
}
