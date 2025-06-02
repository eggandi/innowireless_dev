/** 
  * @file 
  * @brief 식별인증서 발급/다운로드 유틸리티 관련 정의
  * @date 2022-07-28 
  * @author gyun 
  */

#ifndef V2X_SW_ID_CERT_REQ_H
#define V2X_SW_ID_CERT_REQ_H


// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"


#define MAXLINE (255) ///< 라인버퍼 최대길이
#define DEFAULT_LIB_DBG (1) ///< 기본 라이브러리 디버그 메시지 출력 레벨


/**
 * @brief 유틸리티 동작 유형
 */
enum eIdCertReqOperationType
{
  kIdCertReqOperationType_Req, ///< 식별인증서 발급 요청 동작
  kIdCertReqOperationType_Down, ///< 식별인증서 다운로드 동작
  kIdCertReqOperationType_Info, ///< 식별인증서 다운로드일정정보 다운로드 동작
};
typedef unsigned int IdCertReqOperationType; ///< @ref eIdCertReqOperationType


/**
 * @brief 유틸리티 설정 정보
 */
struct IdCertReqCFG
{
  IdCertReqOperationType op; ///< 동작 유형
  unsigned int lib_dbg; ///< V2X 라이브러리 로그메시지 레벨

  char rca_file[MAXLINE + 1]; ///< RootCA 인증서 파일 경로
  char ica_file[MAXLINE + 1]; ///< ICA 인증서 파일 경로
  char pca_file[MAXLINE + 1]; ///< PCA 인증서 파일 경로
  char eca_file[MAXLINE + 1]; ///< ECA 인증서 파일 경로
  char ra_file[MAXLINE + 1]; ///< RA 인증서 파일 경로
  char enroll_cmhf_dir[MAXLINE + 1]; ///< 등록인증서 CMHF를 불러올 디렉토리 경로
  char rca_tls_cert_file[MAXLINE + 1]; ///< RootCA TLS 인증서 파일 경로
  char v_file[MAXLINE + 1]; ///< 서명검증용 임시개인키가 저장될(요청시) 또는 저장된(다운로드시) 파일 경로
  char ck_file[MAXLINE + 1]; ///< 서명검증용 확장함수 키가 저장될(요청시) 또는 저장된(다운로드시) 파일 경로
  char e_file[MAXLINE + 1]; ///< 인증서암호화용 임시개인키가 저장될(요청시) 또는 저장된(다운로드시) 파일 경로
  char ek_file[MAXLINE + 1]; ///< 인증서암호호용 확장함수 키가 저장될(요청시) 또는 저장된(다운로드시) 파일 경로
  char req_h8_file[MAXLINE + 1]; ///< H8(인증서 발급요청문)이 저장될(요청시) 또는 저장된(다운로드시) 파일 경로

  struct {
    char provisiong_req_url[MAXLINE + 1]; ///< 발급요청 메시지를 전송할 URL
    char req_file[MAXLINE + 1]; ///< 인증서 발급요청문이 저장될 파일 경로
    char ack_file[MAXLINE + 1]; ///< 인증서 발급응답문이 저장될 파일 경로
    char cert_dl_time_file[MAXLINE + 1]; ///< 인증서 다운로드시간이 저장될 파일 경로
  } req; ///< 인증서발급요청 동작 전용으로 사용되는 정보

  struct {
    char download_req_url[MAXLINE + 1]; ///< 인증서 다운로드요청 메시지를 전송할 URL
    char cmhf_dir[MAXLINE + 1]; ///< 식별인증서 CMHF가 저장될 디렉토리
    char cert_dir[MAXLINE + 1]; ///< 식별인증서 바이트열이 저장될 디렉토리
    char tmp_zip_file[MAXLINE + 1]; ///< 서버에서 다운로드한 ZIP 파일이 임시로 저장될 파일 경로
    Dot2IdCertTargetTime target_time; ///< 발급받고자 하는 인증서 타겟 시점
  } down; ///< 인증서 다운로드 동작 전용으로 사용되는 정보

  struct {
    char download_info_req_url[MAXLINE + 1]; ///< 다운로드일정정보 다운로드 요청 메시지를 전송할 URL
  } info; ///< 인증서다운로드일정정보 다운로드 동작 전용으로 사용되는 정보
};


/*
 * 전역 변수
 */
extern struct IdCertReqCFG g_cfg;
extern const char *g_default_rca_cert_file;
extern const char *g_default_ica_cert_file;
extern const char *g_default_pca_cert_file;
extern const char *g_default_eca_cert_file;
extern const char *g_default_ra_cert_file;
extern const char *g_default_enroll_cert_cmhf_dir;
extern const char *g_default_id_cert_cmhf_dir;
extern const char *g_default_id_cert_dir;
extern const char *g_default_rca_tls_cert_file;
extern const char *g_default_verify_priv_key_file;
extern const char *g_default_verify_exp_key_file;
extern const char *g_default_cert_encryption_priv_key_file;
extern const char *g_default_cert_encryption_exp_key_file;
extern const char *g_default_id_cert_provisioning_req_h8_file;
extern const char *g_default_id_cert_provisioning_req_file;
extern const char *g_default_id_cert_provisioning_ack_file;
extern const char *g_default_cert_download_time_file;
extern const char *g_default_tmp_zip_file_dir;
extern Dot2IdCertTargetTime g_default_target_time;
extern const char *g_default_id_cert_provisiong_req_url;
extern const char *g_default_id_cert_download_req_url;
extern const char *g_default_id_cert_download_info_req_url;

/*
 * 함수 정의
 */
void ID_CERT_REQ_PrintCFG(void);
int ID_CERT_REQ_ConfigLCM(void);
void ID_CERT_REQ_PrintOcts(const char *desc, const uint8_t *octs, size_t len);
int ID_CERT_REQ_ParsingInputParameters(int argc, char *argv[]);
int ID_CERT_REQ_ExportFile(const char *file_path, const uint8_t *octs, size_t len);
int ID_CERT_REQ_ExportDirFile(const char *dir, const char *filename, const uint8_t *octs, size_t len);
int ID_CERT_REQ_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size);
int ID_CERT_REQ_PrintFile(const char *file_path, const char *str);
int ID_CERT_REQ_RequestIdCertProvisioning(void);
int ID_CERT_REQ_DownloadIdCert(void);
int ID_CERT_REQ_DownloadIdCertDownloadInfo(void);
int ID_CERT_REQ_LoadSCCCertFiles(void);
int ID_CERT_REQ_LoadEnrollmentCMHFFile(void);

#endif //V2X_SW_ID_CERT_REQ_H
