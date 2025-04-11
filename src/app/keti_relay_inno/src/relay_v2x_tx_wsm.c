/**
 * @file
 * @brief
 * @date 2025-04-09
 * @author dong
 */

// 어플리케이션 헤더 파일
#include "relay_main.h"
#include "relay_v2x.h"
#include "relay_v2x_tx.h"
#include "relay_v2x_dot2.h"

static int RELAY_INNO_WSM_Fill_VarLengthNumber(int psid, dot3VarLengthNumber *to);
static int RELAY_INNO_WSM_Header_Fill_Ext(dot3ShortMsgNpdu *wsm, enum relay_inno_wsm_ext_type_e ext_type, const struct realy_inno_wsm_header_ext_data_t *ext_data);
API void _D_F_RELAY_INNO_Fill_TxPrams(struct LTEV2XHALMSDUTxParams *tx_params, ...);

static struct relay_inno_msdu_t g_last_msdu_buf = {0, 0, NULL, 0, {0}};
static struct relay_inno_msdu_t *g_last_msdu = &g_last_msdu_buf;

/**
 * @brief WSM을 생성하여 전송한다.
 * @param[in] wsm_body 전송할 WSM body (=WSDU)
 * @param[in] wsm 전송할 WSM을 저장할 구조체 포인터
 * @param[in] tx_params 전송 파라미터 구조체 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 */
API int RELAY_INNO_MSDU_Transmit(const dot3ShortMsgData *wsm_body, dot3ShortMsgNpdu *wsm, struct LTEV2XHALMSDUTxParams *tx_params)
{
	uint8_t *msdu = NULL;
	if(wsm_body == NULL)
	{
		if(g_last_msdu->isused && g_last_msdu->isfilled)
		{
			return LTEV2XHAL_TransmitMSDU(g_last_msdu->msdu, g_last_msdu->msdu_size, g_last_msdu->tx_params);
		}else{
			_DEBUG_PRINT("Fail to transmit WSM - wsm or wsm_body is NULL\n");
			return -1;
		}
	}

	if(tx_params == NULL)
	{
		RELAY_INNO_Fill_TxPrams(&g_last_msdu->tx_params, g_mib.tx_type,
																				kLTEV2XHALTxFLowIndex_SPS1, 
																				g_mib.tx_priority, 
																				kLTEV2XHALL2ID_Broadcast, 
																				g_mib.tx_power);
		tx_params = &g_last_msdu->tx_params;
	}else{
		memcpy(tx_params, &g_last_msdu->tx_params, sizeof(struct LTEV2XHALMSDUTxParams));
	}

	asn1_ssize_t msdu_size = RELAY_INNO_WSM_Fill_MSDU(wsm, wsm_body, &msdu);
	if(msdu_size < 0 || msdu == NULL) {
		_DEBUG_PRINT("Fail to fill MSDU - RELAY_INNO_WSM_Fill_MSDU() failed: %d\n", msdu_size);
		return -1;
	}

	int ret = LTEV2XHAL_TransmitMSDU(msdu, msdu_size, g_last_msdu->tx_params);
	if(g_last_msdu->isused)
	{
		g_last_msdu->isfilled = true;
		if(g_last_msdu->msdu != NULL)
		{
			free(g_last_msdu->msdu);
			g_last_msdu->msdu = NULL;
		}
		g_last_msdu->msdu = msdu;
		g_last_msdu->msdu_size = msdu_size;
	}else{
		free(msdu);
	}	
	
	return ret;
}

/**
 * @brief LTE-V2X WSM Header를 생성한다.
 * @param[in] wsm_in 생성된 WSM을 저장할 포인터
 * $param[in] tx_psid WSM에 수납할 PSID
 * @param[in] ext_data WSM 확장 헤더에 수납할 데이터
 */
API void RELAY_INNO_WSM_Fill_Header(dot3ShortMsgNpdu **wsm_in, unsigned int tx_psid, struct realy_inno_wsm_header_ext_data_t *ext_data)
{
  int ret;
  _DEBUG_PRINT("Transmit WSM\n");
  /*
   * 입력된 WSM 구조체가 비어있으면 WSM을 구조체를 생성해서 반환
   */
	dot3ShortMsgNpdu *wsm = *wsm_in;
  if(wsm == NULL)
	{
		dot3ShortMsgNpdu *wsm = asn1_mallocz_value(asn1_type_dot3ShortMsgNpdu);
		if (wsm == NULL) {
			_DEBUG_PRINT("Fail to allocate dot3ShortMsgNpdu memory - asn1_mallocz_value() failed\n");
			goto clear;
		}
		*wsm_in = wsm;
	}
  uint8_t *msdu = NULL;
  asn1_ssize_t msdu_size = 0;

  /* N-Header */
  wsm->subtype.choice = dot3ShortMsgSubtype_nullNetworking;
  wsm->subtype.u.nullNetworking.version = 3;

  /* N-Header extension */
  wsm->subtype.u.nullNetworking.nExtensions_option = true;
  wsm->subtype.u.nullNetworking.nExtensions.count = WSM_EXT_CNT;
  wsm->subtype.u.nullNetworking.nExtensions.tab = asn1_mallocz(sizeof(dot3ShortMsgNextension) * WSM_EXT_CNT);
  if (wsm->subtype.u.nullNetworking.nExtensions.tab == NULL) {
    _DEBUG_PRINT("Fail to allocate dot3ShortMsgNextension memory - asn1_mallocz() failed\n");
    goto clear;
  }

  for(int ext_type = 0; ext_type < WSM_EXT_CNT; ext_type++) 
	{
		if(ext_data != NULL) 
		{
			ret = RELAY_INNO_WSM_Header_Fill_Ext(wsm, (enum wsm_ext_type_e)ext_type, ext_data);
		}else{
			ret = RELAY_INNO_WSM_Header_Fill_Ext(wsm, (enum wsm_ext_type_e)ext_type, NULL);
		}
		if(ret < 0) {
			_DEBUG_PRINT("Fail to add WSM extension - RELAY_INNO_WSM_Add_Ext() failed: %d\n", ret);
			goto clear;
		}
	}
  /* T-Header */
  wsm->transport.choice = dot3ShortMsgTpdus_bcMode;
  ret = RELAY_INNO_WSM_Fill_VarLengthNumber(tx_psid, &wsm->transport.u.bcMode.destAddress);
  if (ret < 0) {
    _DEBUG_PRINT("Fail to fill destAddress(VarLengthNumber) - WSM_FillVarLengthNumber() failed: %d\n", tx_psid);
    goto clear;
  }
	
	return;

clear:
	if (wsm != NULL) {
    asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm);
    wsm = NULL;
  }
	return;
}
/**
 * @brief WSM 헤더를 해제한다.
 * @param[in] wsm WSM 헤더 포인터
 */
API void RELAY_INNO_WSM_Free_Header(dot3ShortMsgNpdu *wsm)
{
	if(wsm != NULL) {
		asn1_free_value(asn1_type_dot3ShortMsgNpdu, wsm);
		wsm = NULL;
	}
	return;
}
/**
 * @brief WSM 송신 파라미터를 설정한다.
 * @details 송신 파라미터는 다음과 같다.
 * - tx_type: 송신 타입 (SPS, SPS1, SPS2, SPS3)
 * - tx_flow_index: 송신 플로우 인덱스 (SPS1, SPS2, SPS3)
 * - priority: 송신 우선순위 (0~7)
 * - dst_l2_id: 송신 목적지 L2 ID (0~255)
 * - tx_power: 송신 전력 (dBm)
 * @note 송신 플로우 인덱스는 SPS 타입에서만 사용된다.
 * @note 송신 우선순위는 Ad-Hoc 타입에서만 사용된다.
 * @note 송신 목적지 L2 ID는 Ad-Hoc 타입에서만 사용된다.
 * @note 송신 전력은 Ad-Hoc 타입에서만 사용된다.
 * @param[in] tx_params 송신 파라미터 구조체 포인터
 * @param[in] ... 송신 파라미터 값들 (0xFFFFFFFF로 종료)
 * @retval void
 */
API void _D_F_RELAY_INNO_Fill_TxPrams(struct LTEV2XHALMSDUTxParams *tx_params, ...)
{
	va_list args;
	va_start(args, tx_params);

	memset(tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
	int index = 0;
	while(1)
	{
		int arg = va_arg(args, int);
		if(arg ==  0xFFFFFFFF) break;
		switch(index)
		{
			case 0:
				tx_params->tx_type = (unsigned int)arg;
				break;
			case 1:
				tx_params->tx_flow_index = (unsigned int)arg;
				break;
			case 2:
				tx_params->priority = (unsigned int)arg;
				break;
			case 3:
				tx_params->dst_l2_id = (unsigned int)arg;
				break;
			case 4:
				tx_params->tx_power = (int)arg;
				break;
			default:
				break;
		}
		index++;
	}

	va_end(args);

	return;
}

/**
 * @brief MSDU를 생성한다.
 * @param[in] wsm 전송할 WSM을 저장할 구조체 포인터
 * @param[in] wsm_body 전송할 WSM body (=WSDU)
 * @param[out] msdu_in 생성된 MSDU를 저장할 포인터
 * @retval 0: 성공
 * @retval -1: 실패
 */
API asn1_ssize_t RELAY_INNO_WSM_Fill_MSDU(const dot3ShortMsgNpdu *wsm, const dot3ShortMsgData *wsm_body, uint8_t **msdu_in)
{
	uint8_t *msdu = *msdu_in;
  asn1_ssize_t msdu_size = 0;
	if(wsm_body == NULL)
	{
		_DEBUG_PRINT("Empty wsm body ptr: %p\n", wsm_body);
		return -1;
	}
	if(msdu != NULL)
	{
		free(msdu);
		msdu = NULL;
	}

	if(wsm == NULL)
	{
		_DEBUG_PRINT("Empty wsm ptr: %p\n", wsm);
		RELAY_INNO_WSM_Fill_Header(&wsm, NULL);
	}else{
		if(wsm->body.len > 0 || wsm->body.buf != NULL)
		{
			_DEBUG_PRINT("Free wsm body buffer: %p\n", wsm->body.buf);
			asn1_free_value(asn1_type_dot3ShortMsgData, wsm->body);
		}
	}

	wsm->body.len = wsm_body->len;
	wsm->body.buf = wsm_body->buf;
	msdu_size = asn1_uper_encode(&msdu, asn1_type_dot3ShortMsgNpdu, wsm);
	if (msdu_size < 0 || msdu == NULL) {
    _DEBUG_PRINT("Fail to encode dot3ShortMsgNpdu - asn1_uper_encode() failed: %d\n", msdu_size);
    goto clear;
  }
	*msdu_in = msdu;
	return msdu_size;

clear:
  if (msdu != NULL) {
    free(msdu);
    msdu = NULL;
  }
	return -1;
}

/**
 * @brief ASN.1 정보구조체 내 VarLengthNumber(Psid) 필드를 채운다.
 * * @param[in] from 메시지 생성을 위한 정보 파라미터 구조체 포인터 (API context)
 * * @param[out] to 정보가 채워질 필드의 구조체 포인터 (ASN.1 context)
 * * @retval 0: 성공
 * * @retval 음수(-Cvcoctci3ResultCode): 실패
 */
static int RELAY_INNO_WSM_Fill_VarLengthNumber(int psid, dot3VarLengthNumber *to)
{
	/*
	 * p-encoded Psid 값의 길이에 맞게 VarLengthNumber 정보구조체를 채운다.
	 */
	switch ((psid > 127) + (psid > 16511) + (psid > 2113663) + (psid > 270549119)) 
	{
		case 3:
			to->choice = dot3VarLengthNumber_extension;
			to->u.extension.choice = dot3Ext1_extension;
			to->u.extension.u.extension.choice = dot3Ext2_extension;
			to->u.extension.u.extension.u.extension.choice = dot3Ext3_extension;
			to->u.extension.u.extension.u.extension.u.content = (int) psid;
			break;
    case 2:
			to->choice = dot3VarLengthNumber_extension;
			to->u.extension.choice = dot3Ext1_extension;
			to->u.extension.u.extension.choice = dot3Ext2_content;
			to->u.extension.u.extension.u.content = (int) psid;
			break;
    case 1:
			to->choice = dot3VarLengthNumber_extension;
			to->u.extension.choice = dot3Ext1_content;
			to->u.extension.u.content = (int) psid;
			break;
    case 0:
			to->choice = dot3VarLengthNumber_content;
			to->u.content = (int) psid;
			break;
		default:
			return -1;
	}

  return 0;
}

/**
 * @brief WSM 헤더 Ext를 채운다.
 * @param[in] wsm WSM 구조체 포인터
 * @param[in] ext_type 확장 헤더 타입
 * @param[in] ext_data 확장 헤더 데이터 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Cvcoctci3ResultCode): 실패
 */
static int RELAY_INNO_WSM_Header_Fill_Ext(dot3ShortMsgNpdu *wsm, enum wsm_ext_type_e ext_type, const struct realy_inno_wsm_header_ext_data_t *ext_data)
{
	dot3ShortMsgNextension *ext = &wsm->subtype.u.nullNetworking.nExtensions.tab[ext_type];
	switch(ext_type)
	{
		case RELAY_INNO_WSM_EXT_ID_TX_POWER: // TX_POWER
		{
			ext->extensionId = WSM_EXT_ID_TX_POWER;
			ext->value.type = (ASN1CType *) asn1_type_dot3TXpower80211;
			ext->value.u.data = asn1_mallocz_value(ext->value.type);
			if(ext->value.u.data != NULL) 
			{
				if(ext_data != NULL) 
				{
					memcpy(ext->value.u.data, &ext_data->tx_power, sizeof(dot3TXpower80211));
				}else{
					memcpy(ext->value.u.data, &g_mib.tx_power, sizeof(dot3TXpower80211));
				}
			}else{
				return -1;
			}
			break;
		}
		case RELAY_INNO_WSM_EXT_ID_CHANNEL: // CHANNEL
		{
			ext->extensionId = WSM_EXT_ID_CHANNEL;
			ext->value.type = (ASN1CType *) asn1_type_dot3ChannelNumber80211;
			ext->value.u.data = asn1_mallocz_value(ext->value.type);
			if(ext->value.u.data != NULL) 
			{
				if(ext_data != NULL) 
				{
					memcpy(ext->value.u.data, &ext_data->tx_channel_num, sizeof(dot3ChannelNumber80211));
				}else{
					memcpy(ext->value.u.data, &g_mib.tx_chan_num, sizeof(dot3ChannelNumber80211));
				}
			}else{
				return -2;
			}
			break;
		}
		case RELAY_INNO_WSM_EXT_ID_DATERATE: // DATERATE
		{
			ext->extensionId = WSM_EXT_ID_DATERATE;
			ext->value.type = (ASN1CType *) asn1_type_dot3DataRate80211;
			ext->value.u.data = asn1_mallocz_value(ext->value.type);
			if(ext->value.u.data != NULL) 
			{
				if(ext_data != NULL) 
				{
					memcpy(ext->value.u.data, &ext_data->tx_datarate, sizeof(dot3DataRate80211));
				}else{
					memcpy(ext->value.u.data, &g_mib.tx_datarate, sizeof(dot3DataRate80211));
				}				
			}else{
				return -3;
			}
			break;
		}
		default:
			break;
	}

	return 0;
}
	
