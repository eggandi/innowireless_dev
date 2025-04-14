#include "relay_v2x_j2735_bsm.h"
#include "relay_config.h"

extern struct relay_inno_gnss_data_t *G_gnss_data;
extern struct relay_inno_gnss_data_bsm_t *G_gnss_bsm_data;

static struct j2735BSMcoreData *g_core; 
static bool g_bsm_core_data_installed = false; 

static uint8_t g_msg_bsm_tx_cnt = 0; 
static uint8_t g_temporary_id[RELAY_INNO_TEMPORARY_ID_LEN] = { 0x00, 0x01, 0x02, 0x03 }; 
static int g_transmission = 0; // neutral
static int g_angle = 0; 
static int g_traction = 0; // unavailable
static int g_abs = 1; // off
static int g_scs = 2; // on
static int g_brake_boost = 2; // on
static int g_aux_brakes = 2; // on
static int g_wheel_brakes_unavailable = 1; // true
static int g_wheel_brakes_left_front = 0; // false
static int g_wheel_brakes_left_rear = 1; // true
static int g_wheel_brakes_right_front = 2; // false
static int g_wheel_brakes_right_rear = 3; // true
static int g_vehicle_length = 1000; 
static int g_vehicle_width = 1001; 


static int RELAY_INNO_BSM_SecMark(); 
static int RELAY_INNO_BSM_Fill_CoreData(struct j2735BSMcoreData *core_ptr); 

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

  frame->messageId = 20; // BasicSafetyMessage (per SAE j2735)
  frame->value.type = (ASN1CType *)asn1_type_j2735BasicSafetyMessage;
  frame->value.u.data = bsm;

  // BSM을 인코딩한다.
  *bsm_size = (size_t)asn1_uper_encode(&buf, asn1_type_j2735MessageFrame, frame);
  if (buf == NULL) {
    _DEBUG_PRINT("Fail to encode BSM - asn1_uper_encode() failed\n");
    goto out;
  }else{
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
		}
	}

	ret = RELAY_INNO_BSM_Fill_CoreData(&bsm->coreData);
	if(ret < 0)
	{
		_DEBUG_PRINT("Fail to fill BSM core data\n");
		return ret;
	}
	bsm->partII_option = false;
	bsm->regional_option = false;
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
	printf("core_ptr: %p\n", core);
	if(G_gnss_bsm_data->isused == true)
	{
		if(g_core != NULL)
		{
			asn1_copy_value(asn1_type_j2735BSMcoreData, core, g_core);_DEBUG_LINE
		}
	}
	printf("core_ptr: %p\n", core);

  if(G_gnss_data->status.unavailable == FALSE)
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

static int RELAY_INNO_BSM_SecMark()
{
	struct timespec tv;
	clock_gettime(CLOCK_REALTIME, &tv); 
	struct tm *tm;
	tm = localtime(&tv.tv_sec);
	int ret = 0;
	ret += tm->tm_sec * 1000;
	ret += (int)((tv.tv_nsec)/1000000);
	
	return ret % 65536;
}
