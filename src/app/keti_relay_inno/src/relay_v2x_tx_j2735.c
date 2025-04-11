/**
 * @file
 * @brief
 * @date 2025-04-09
 * @author dong
 */

#include "relay_v2x_tx_j2735.h"

/**
 * @brief BSM을 전송한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
API int RELAY_INNO_V2X_Tx_J2735_BSM()
{
	uint8_t *spdu_payload_bsm = NULL;
	size_t spdu_payload_bsm_size = 0;
	spdu_payload_bsm = REPLAY_INNO_J2736_Construct_BSM(size_t *bsm_size);

	if(spdu_payload_bsm == NULL)
	{
		_DEBUG_PRINT("Fail to construct BSM - REPLAY_INNO_J2736_Construct_BSM() failed\n");
		return -1;
	}
	/*
   * Signed SPDU를 생성한다.
	 */
	struct Dot2SPDUConstructParams params;
	struct Dot2SPDUConstructResult res;
	memset(&params, 0, sizeof(params));
	params.type = kDot2SPDUConstructType_Signed;
	params.signed_data.psid = BSM_PSID;
	params.signed_data.signer_id_type = kDot2SignerId_Profile;
	params.signed_data.cmh_change = false;
re_ContstructSPDU:
	res = RELAY_INNO_Dot2_ConstrustSPDU(&params, spdu_payload_bsm, spdu_payload_bsm_size);
	if (res.ret < 0) {
		Err("BSM tx callback - Dot2_ConstructSPDU() failed: %d\n", res.ret);
		return;
	}
	if(res.cmh_expiry == true)
	{
		goto re_ContstructSPDU;
		params.signed_data.signer_id_type = kDot2SignerId_Certificate;
		params.signed_data.cmh_change = true;
	}

#ifdef _USED_DOT3_LIB
#else
	struct LTEV2XHALMSDUTxParams tx_params;
	memset(&tx_params, 0x00, sizeof(struct LTEV2XHALMSDUTxParams));
	tx_params.tx_type = kLTEV2XHALTxFlowType_SPS;
	tx_params.tx_flow_index = kLTEV2XHALTxFLowIndex_SPS1;
	tx_params.priority = kLTEV2XHALPriority_NA;
	tx_params.tx_power = kDot3Power_NA;
	tx_params.dst_l2_id = BSM_PSID;
	int ret = RELAY_INNO_MSDU_Transmit(res.spdu, res.spdu_size, &tx_params);
	if (ret < 0) {
		Err("Fail to transmit BSM - RELAY_INNO_MSDU_Transmit() failed: %d\n", ret);
		return -2;
	}

#endif
	return 0;
}