/** 
 * @file
 * @brief
 * @date 2020-10-17
 * @author gyun
 */


#ifndef V2X_SW_SEC_TESTER_H
#define V2X_SW_SEC_TESTER_H


/// Burst 모드에서 테스트 횟수
#define BURST_MODE_TEST_CNT (100000u)


/**
 * @brief 동작 유형
 */
enum eOperation
{
  kOperation_MsgGenerate,
  kOperation_MsgProcess,
};
typedef unsigned int Operation;


/**
 * @brief 동작 모드
 */
enum eMode
{
  kMode_Single, ///< 1회의 테스트를 수행하여 처리시간을 측정한다.
  kMode_Burst, ///< BURST_MODE_TEST_CNT회의 테스트를 수행하여 평균 처리시간 및 초당 처리개수를 측정한다.
  kMode_Check ///< 메시지 처리 동작이 잘 동작하는지 확인한다.
};
typedef unsigned int Mode;


/*
 * 전역 변수 정의
 */
extern Operation g_op;
extern Mode g_mode;
extern bool g_relevance_consistency_check;
extern uint8_t g_sample_spdu[];
extern size_t g_sample_spdu_size;
extern uint8_t g_sample_rse_0_cert[];
extern Dot2PSID g_sample_rse_0_psid;
extern Dot2Time64 g_sample_rse_0_valid_start;
extern Dot2Latitude g_sample_rse_0_valid_lat;
extern Dot2Longitude g_sample_rse_0_valid_lon;
extern Dot2Elevation g_sample_rse_0_valid_elev;
extern uint8_t g_sample_rse_0_cmhf2[];
extern size_t g_sample_rse_0_cmhf2_size;
extern uint8_t g_sample_pca_cert[];
extern size_t g_sample_pca_cert_size;
extern uint8_t g_sample_ica_cert[];
extern size_t g_sample_ica_cert_size;
extern uint8_t g_sample_rca_cert[];
extern size_t g_sample_rca_cert_size;

/*
 * 함수 프로토타입
 */
int SEC_TESTER_RegisterCryptoMaterials(void);
void SEC_TESTER_MsgGenerateTest(void);
void SEC_TESTER_ProcessSPDUCallback(Dot2ResultCode result, void *priv);
void SEC_TESTER_ProcessRxMPDUCallback(const uint8_t *mpdu, WalMPDUSize mpdu_size, const struct WalMPDURxParams *rx_params);
void SEC_TESTER_SampleMsgProcessTest(void);
void SEC_TESTER_MsgProcessTest(void);


#endif //V2X_SW_SEC_TESTER_H
