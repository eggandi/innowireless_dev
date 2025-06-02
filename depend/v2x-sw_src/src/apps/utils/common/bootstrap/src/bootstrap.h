/** 
  * @file 
  * @brief 부트스트래핑 유틸리티 관련 정의
  * @date 2022-07-17 
  * @author gyun 
  */

#ifndef V2X_SW_BOOTSTRAP_H
#define V2X_SW_BOOTSTRAP_H


// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"


#define MAXLINE (255) ///< 라인버퍼 최대길이
#define DEFAULT_LIB_DBG (1) ///< 기본 라이브러리 디버그 메시지 출력 레벨


/**
 * @brief 유틸리티 동작 유형
 */
enum eBootstrapOperationType
{
  kBootstrapOperationType_Gen, ///< 등록인증서 발급요청문 생성 동작
  kBootstrapOperationType_Proc, ///< 등록인증서 발급응답문 처리 동작
};
typedef unsigned int BootstrapOperationType; ///< @ref eBootstrapOperationType


/**
 * @brief 부트스트래핑 설정 정보
 */
struct BootstrapCFG
{
  BootstrapOperationType op; ///< 부트스트래핑 동작 유형
  unsigned int lib_dbg; ///< V2X 라이브러리 로그메시지 레벨

  char init_priv_key_file[MAXLINE+1]; ///< 등록인증서 초기(임시)개인키가 저장될/저장된 파일명

  struct {
    Dot2Time32 valid_start; ///< 등록인증서 유효기간 시작시점
    Dot2CertDurationType dur_type; ///< 등록인증서 유효기간 유형
    uint16_t dur; ///< 등록인증서 유효기간
    Dot2IdentifiedRegionNum region_num; ///< 등록인증서 내 유효지역 개수
    Dot2CountryCode region[kDot2IdentifiedRegionNum_Max]; ///< 등록인증서 내 유효지역 식별자(들)
    Dot2CertPermissionNum psid_num; ///< 등록인증서 내 권한 개수
    Dot2PSID psid[kDot2CertPermissionNum_Max]; ///< 등록인증서 내 권한(들)
    char ecreq_file[MAXLINE+1]; ///< 등록인증서 발급요청문이 저장될 파일명
  } gen;
  struct {
    bool ecresp_file_present; ///< 등록인증서 발급응답문 바이트열 처리 여부
    char ecresp_file[MAXLINE+1]; ///< 등록인증서 발급응답문 바이트열이 저장된 파일명
    char enroll_cert_file[MAXLINE+1]; ///< 등록인증서가 저장된 파일명
    char recon_priv_file[MAXLINE+1]; ///< 등록인증서 개인키재구성값이 저장된 파일명
    char rca_cert_file[MAXLINE+1]; ///< RCA 인증서가 저장된 파일명
    char eca_cert_file[MAXLINE+1]; ///< ECA 인증서가 저장된 파일명
    char ra_cert_file[MAXLINE+1]; ///< RA 인증서가 저장된 파일명
    char lccf_file[MAXLINE+1]; ///< LCCF 바이트열이 저장된 파일명
    char ica_cert_file[MAXLINE+1]; ///< ICA 인증서가 저장될 파일명
    char pca_cert_file[MAXLINE+1]; ///< PCA 인증서가 저장될 파일명
    char crlg_cert_file[MAXLINE+1]; ///< CRLG 인증서가 저장될 파일명
    char enroll_priv_key_file[MAXLINE+1]; ///< 최종(재구성된) 등록인증서 개인키가 저장될 파일명
  } proc;
};


/*
 * 전역변수
 */
extern const char *g_default_cert_valid_duration;
extern const char *g_default_region;
extern const char *g_default_cert_psid;
extern const char *g_default_rca_cert_file;
extern const char *g_default_ica_cert_file;
extern const char *g_default_pca_cert_file;
extern const char *g_default_eca_cert_file;
extern const char *g_default_ra_cert_file;
extern const char *g_default_crlg_cert_file;
extern const char *g_default_lccf_file;
extern const char *g_default_init_priv_key_file;
extern const char *g_default_ecreq_file;
extern const char *g_default_enroll_cert_file;
extern const char *g_default_enroll_recon_priv_file;
extern const char *g_default_enroll_priv_key_file;
extern struct BootstrapCFG g_cfg; ///< 부트스트래핑 설정정보


/*
 * 함수 정의
 */
int BOOTSTRAP_ParsingInputParameters(int argc, char *argv[]);
void BOOTSTRAP_PrintBootstrapCFG(void);
void BOOTSTRAP_PrintOcts(const char *desc, const uint8_t *octs, size_t len);
int BOOTSTRAP_GenerateECRequest(void);
int BOOTSTARP_ExportFile(const char *file_path, const uint8_t *octs, size_t len);
int BOOTSTRAP_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size);
int BOOTSTRAP_ProcessECResponse(void);


#endif //V2X_SW_BOOTSTRAP_H
