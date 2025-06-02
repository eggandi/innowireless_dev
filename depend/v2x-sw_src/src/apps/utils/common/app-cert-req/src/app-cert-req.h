/** 
  * @file 
  * @brief 응용인증서 발급/다운로드 유틸리티 관련 정의
  * @date 2022-07-28 
  * @author gyun 
  */

#ifndef V2X_SW_APP_CERT_REQ_H
#define V2X_SW_APP_CERT_REQ_H


// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"


#define MAXLINE (255) ///< 라인버퍼 최대길이
#define DEFAULT_LIB_DBG (1) ///< 기본 라이브러리 디버그 메시지 출력 레벨


/**
 * @brief 유틸리티 동작 유형
 */
enum eAppCertReqOperationType
{
  kAppCertReqOperationType_Req, ///< 응용인증서 발급 요청 동작
  kAppCertReqOperationType_Down, ///< 응용인증서 다운로드 동작
  kAppCertReqOperationType_LPF, ///< LPF 다운로드 동작
  kAppCertReqOperationType_LCCF, ///< LCCF 다운로드 동작
};
typedef unsigned int AppCertReqOperationType; ///< @ref eAppCertReqOperationType


/**
 * @brief 유틸리티 설정 정보
 */
struct AppCertReqCFG
{
  AppCertReqOperationType op; ///< 동작 유형
  unsigned int lib_dbg; ///< V2X 라이브러리 로그메시지 레벨

  char rca_file[MAXLINE + 1]; ///< RootCA 인증서 파일 경로
  char ica_file[MAXLINE + 1]; ///< ICA 인증서 파일 경로
  char pca_file[MAXLINE + 1]; ///< PCA 인증서 파일 경로
  char eca_file[MAXLINE + 1]; ///< ECA 인증서 파일 경로
  char ra_file[MAXLINE + 1]; ///< RA 인증서 파일 경로
  char enroll_cmhf_dir[MAXLINE + 1]; ///< 등록인증서 CMHF를 불러올 디렉토리 경로
  char rca_tls_cert_file[MAXLINE + 1]; ///< RootCA TLS 인증서 파일 경로
  char v_file[MAXLINE + 1]; ///< 서명검증용 임시개인키가 저장될(요청시) 또는 저장된(다운로드시) 파일 경로
  char e_file[MAXLINE + 1]; ///< 인증서암호화용 임시개인키가 저장될(요청시) 또는 저장된(다운로드시) 파일 경로
  char req_h8_file[MAXLINE + 1]; ///< 인증서 발급요청문 H8이 저장될(요청시) 또는 저장된(다운로드시) 파일 경로

  struct {
    char provisiong_req_url[MAXLINE + 1]; ///< 발급요청 메시지를 전송할 URL
    char cert_dl_time_file[MAXLINE + 1]; ///< 인증서 다운로드시간이 저장될 파일 경로
    char req_file[MAXLINE + 1]; ///< 인증서 발급요청문이 저장될 파일 경로
    char ack_file[MAXLINE + 1]; ///< 인증서 발급응답문이 저장될 파일 경로
  } req;

  struct {
    char download_req_url[MAXLINE + 1]; ///< 다운로드요청 메시지를 전송할 URL
    char cmhf_dir[MAXLINE + 1]; ///< 응용인증서 CMHF가 저장될 파일 경로
    char cert_dir[MAXLINE + 1]; ///< 응용인증서 바이트열이 저장될 파일 경로
    char tmp_zip_file[MAXLINE + 1]; ///< 서버에서 다운로드한 ZIP 파일이 임시로 저장될 파일 경로
  } down;

  struct {
    char download_url[MAXLINE + 1]; ///< LPF를 다운로드할 URL
    char current_filename[MAXLINE + 1]; ///< 이미 가지고 있는 LPF 파일 이름
    bool current_filename_present; ///< LPF 파일 이름 존재 여부
  } lpf;

  struct {
    char download_url[MAXLINE + 1]; ///< LCCF를 다운로드할 URL
    char current_filename[MAXLINE + 1]; ///< 이미 가지고 있는 LCCF 파일 이름
    bool current_filename_present; ///< LCCF 파일 이름 존재 여부
    char crlg_file[MAXLINE + 1]; ///< CRLG 인증서 파일 경로
  } lccf;
};


/*
 * 전역 변수
 */
extern struct AppCertReqCFG g_cfg;
extern const char *g_default_rca_cert_file;
extern const char *g_default_ica_cert_file;
extern const char *g_default_pca_cert_file;
extern const char *g_default_eca_cert_file;
extern const char *g_default_ra_cert_file;
extern const char *g_default_crlg_cert_file;
extern const char *g_default_enroll_cert_cmhf_dir;
extern const char *g_default_app_cert_cmhf_dir;
extern const char *g_default_app_cert_dir;
extern const char *g_default_rca_tls_cert_file;
extern const char *g_default_verify_priv_key_file;
extern const char *g_default_cert_encryption_priv_key_file;
extern const char *g_default_app_cert_provisioning_req_h8_file;
extern const char *g_default_app_cert_provisioning_req_file;
extern const char *g_default_app_cert_provisioning_ack_file;
extern const char *g_default_cert_download_time_file;
extern const char *g_default_tmp_zip_file_dir;
extern const char *g_default_app_cert_provisiong_req_url;
extern const char *g_default_app_cert_download_req_url;
extern const char *g_default_lpf_download_url;
extern const char *g_default_lccf_download_url;

/*
 * 함수 정의
 */
void APP_CERT_REQ_PrintCFG(void);
int APP_CERT_REQ_ConfigLCM(void);
void APP_CERT_REQ_PrintOcts(const char *desc, const uint8_t *octs, size_t len);
int APP_CERT_REQ_ParsingInputParameters(int argc, char *argv[]);
int APP_CERT_REQ_ExportFile(const char *file_path, const uint8_t *octs, size_t len);
int APP_CERT_REQ_ExportDirFile(const char *dir, const char *filename, const uint8_t *octs, size_t len);
int APP_CERT_REQ_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size);
int APP_CERT_REQ_PrintFile(const char *file_path, const char *str);
int APP_CERT_REQ_RequestAppCertProvisioning(void);
int APP_CERT_REQ_DownloadAppCert(void);
int APP_CERT_REQ_LoadSCCCertFiles(void);
int APP_CERT_REQ_LoadEnrollmentCMHFFile(void);
int APP_CERT_REQ_DownloadLPF(void);
int APP_CERT_REQ_DownloadLCCF(void);

#endif //V2X_SW_APP_CERT_REQ_H
