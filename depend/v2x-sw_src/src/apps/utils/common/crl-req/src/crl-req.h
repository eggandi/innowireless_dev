/**
  * @file
  * @brief CRL 다운로드 유틸리티 관련 정의
  * @date 2022-12-10
  * @author gyun
  */

#ifndef V2X_SW_CRL_REQ_H
#define V2X_SW_CRL_REQ_H

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"

#define MAXLINE (255) ///< 라인버퍼 최대길이
#define DEFAULT_LIB_DBG (1) ///< 기본 라이브러리 디버그 메시지 출력 레벨


/**
 * @brief 유틸리티 동작 유형
 */
enum eCRLReqOperationType
{
  kCRLReqOperationType_Download, ///< CRL 다운로드 요청 동작
  kCRLReqOperationType_Load, ///< CRL 로딩 동작
};
typedef unsigned int CRLReqOperationType; ///< @ref eCRLReqOperationType


/**
 * @brief 유틸리티 설정 정보
 */
struct CRLReqCFG
{
  CRLReqOperationType op; ///< 동작 유형
  unsigned int lib_dbg; ///< V2X 라이브러리 로그메시지 레벨

  char rca_file[MAXLINE + 1]; ///< RootCA 인증서 파일 경로
  char ica_file[MAXLINE + 1]; ///< ICA 인증서 파일 경로
  char pca_file[MAXLINE + 1]; ///< PCA 인증서 파일 경로
  char ra_file[MAXLINE + 1]; ///< RA 인증서 파일 경로
  char crl_file[MAXLINE + 1]; ///< CRL 파일 경로

  struct {
    char rca_tls_cert_file[MAXLINE + 1]; ///< RootCA TLS 인증서 파일 경로
    char req_url[MAXLINE + 1]; ///< 다운로드요청 메시지를 전송할 URL
  } down; // Download 동작용 설정정보

  struct {
    char crlg_file[MAXLINE + 1]; ///< CRLG 인증서 파일 경로
  } load; // Load 동작용 설정정보
};


/*
 * 전역 변수
 */
extern struct CRLReqCFG g_cfg;
extern const char *g_default_rca_cert_file;
extern const char *g_default_ica_cert_file;
extern const char *g_default_pca_cert_file;
extern const char *g_default_ra_cert_file;
extern const char *g_default_crlg_cert_file;
extern const char *g_default_rca_tls_cert_file;
extern const char *g_default_req_url;
extern const char *g_default_crl_file;


/*
 * 함수 정의
 */
void CRL_REQ_PrintCFG(void);
int CRL_REQ_ConfigLCM(void);
void CRL_REQ_PrintOcts(const char *desc, const uint8_t *octs, size_t len);
int CRL_REQ_ParsingInputParameters(int argc, char *argv[]);
int CRL_REQ_ExportFile(const char *file_path, const uint8_t *octs, size_t len);
int CRL_REQ_ExportDirFile(const char *dir, const char *filename, const uint8_t *octs, size_t len);
int CRL_REQ_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size);
int CRL_REQ_PrintFile(const char *file_path, const char *str);
int CRL_REQ_LoadSCCCertFiles(void);
int CRL_REQ_DownloadCRL(void);
int CRL_REQ_LoadCRLFile(void);


#endif //V2X_SW_CRL_REQ_H
