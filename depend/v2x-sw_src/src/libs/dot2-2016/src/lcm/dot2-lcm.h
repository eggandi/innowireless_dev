/** 
  * @file 
  * @brief 
  * @date 2022-05-01 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_LCM_H
#define V2X_SW_DOT2_LCM_H


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"

/// 정상을 나타내는 HTTPS 코드
#define DOT2_HTTPS_CODE_OK (200)
/// 수정되지 않았음을 나타내는 HTTPS 코드
#define DOT2_HTTPS_CODE_NOT_MODIFIED (304)
/// 서버에서 현재 시스템 부하 등으로 인해 정확한 다운로드 시간을 제공할 수 없는 경우 (다음번에 다시 시도 필요)
#define DOT2_HTTPS_CODE_DOWNLOAD_INFO_UNAVAILABLE (5065)
/// A사 서버에 중복 발급요청문 전송 시 리턴값
#define DOT2_HTTPS_CODE_INTERNAL_SERVER_ERROR (500)
/// 서버의 HTTPS 응답대기시간 타임아웃(밀리초단위) - 이 시간까지 응답이 성공적으로 수신되지 않으면 curl_easy_perfomr()이 리턴된다.
#define DOT2_HTTPS_RESPONSE_WAIT_TIMEOUT (10000)


/**
 * @brief 표준에 정의된 ScmsPDU 버전
 */
enum eDot2ScmsPDUVersion
{
  KDot2ScmsPDUVersion_SCMS = 1,
};
typedef unsigned int Dot2ScmsPDUVersion; ///< @ref eDot2ScmsPDUVersion


/**
 * @brief CrlSeries 값
 *
 * KCAC.V2X.CRLPROF V2X 인증서 폐지목록 프로파일 규격 v1.1 (2020.11) 부록.1 참조
 */
enum eDot2CrlSeries
{
  kDot2CrlSeries_ObuPseudonymCrlSeries = 1, ///< 익명인증서
  kDot2CrlSeries_ScmsComponentCrlSeries = 2, ///< ica/eca/pca/ra 인증서
  kDot2CrlSeries_EeNonPseudonymCrlSeries = 3, ///< 응용/식별 인증서
  kDot2CrlSeries_EeEnrollmentCrlSeries = 4, ///< 등록인증서
  kDot2CrlSeries_SpclComponentCrlSeries = 256, ///< PG/MA/CRLG 인증서
};


/**
 * @brief 인증서폐기정보 엔트리 개수
 */
enum eDot2CertRevocationEntryNum
{
  kDot2CertRevocationEntryNum_Min = 0,
  kDot2CertRevocationEntryNum_Max = 10000, ///< 엔트리 최대기수(임의로 정의)
};
typedef unsigned int Dot2CertRevocationEntryNum; ///< @ref eDot2CertRevocationEntryNum


/**
 * @brief LV 기반 CRL 엔트리 개수
 */
enum eDot2LVBasedCRLEntryNum
{
  kDot2LVBasedCRLEntryNum_Min = 0,
  kDot2LVBasedCRLEntryNum_Max = 10000, ///< 엔트리 최대기수(임의로 정의)
};
typedef unsigned int Dot2LVBasedCRLEntryNum; ///< @ref eDot2LVBasedCRLEntryNum


/**
 * @brief HTTPS로 교환되는 메시지 정보
 */
struct Dot2HTTPSMessage
{
  uint8_t *octs; ///< 메시지 바이트열
  size_t len; ///< 메시지 바이트열의 길이
};


/**
 * @brief HTTPS로 교환되는 파일명 정보
 */
struct Dot2HTTPSFileName
{
  int res; ///< 파일명 저장 결과
  char str[DOT2_HTTP_FILE_NAME_MAX_LEN+1]; ///< 파일명
};


/**
 * @brief HTTPS 접속 정보
 */
struct Dot2HTTPSConnInfo
{
  char *lpf_url; ///< LPF 요청 URL
  char *lccf_url; ///< LPF 요청 URL
  char *crl_url; ///< CRL 요청 URL
  char *acp_url; ///< 응용인증서 발급요청 URL
  char *pcp_url; ///< 익명인증서 발급요청 URL
  char *icp_url; ///< 식별인증서 발급요청 URL
  char *rca_tls_cert_file_path; ///< root CA TLS 인증서 파일경로
};


/**
 * @brief 인증서요청 관련 정보
 *
 * 인증서 발급/다운로드를 위해 필요한 정보들의 모음
 * MIB에 저장되어 있는 정보가 복사된다.
 * 아래 정보들은 dot2 라이브러리 내 임계영역에 속하는 정보로써,
 * 인증서 발급/다운로드 동작 동안 해당 정보를 지속적으로 사용하기 위해서는 MIB에 대한 뮤텍스 락을 잡고 있어야 한다.
 * 이를 피하기 위해 해당 정보들을 본 구조체에 복사해서 사용한다. (복사하는 동안만 뮤텍스 락을 잡으면 된다)
 */
struct Dot2CertRequestInfo
{
  struct {
    struct Dot2SHA256 cert_h; ///< 인증서해시 (요청문 암호화에 사용된다)
    struct Dot2ECPublicKey enc_pub_key; ///< 암호화용 공개키 (요청문 암호화에 사용된다)
    EC_KEY *eck_verify_pub_key; ///< 서명검증용공개키 (요청 응답문 서명검증에 사용된다)
  } ra; ///< RA 인증서 관련 정보

  struct {
    struct Dot2SHA256 cert_h; ///< 인증서해시 (다운로드 응답문 서명검증에 사용된다)
    struct Dot2ECPublicKey pub_key; ///< 공개키 (CMHF 생성에 사용된다)
    EC_KEY *eck_pub_key; ///< 공개키 (다운로드 응답문 서명검증에 사용된다)
  } pca; ///< ACA/PCA 인증서 관련 정보

  struct Dot2HTTPSConnInfo https; ///< HTTPS 접속 정보

  struct {
    Dot2Time32 valid_start; ///< 유효기간 시작시점
    struct Dot2SHA256 cert_h; ///< 인증서해시 (요청문 서명생성에 사용된다)
    EC_KEY *eck_priv_key; ///< 개인키 (요청문 서명생성에 사용된다)
    void *asn1_cert; ///< 디코딩 정보 (요청문 내 Signer 필드에 수납된다)
  } ec; ///< 등록인증서 관련 정보

  char *tmp_zip_file_path; ///< 동작 중 다운로드한 ZIP 파일이 임시 저장될 파일 경로 (예: "down.zip", "/tmp/down.zip")
};


/**
 * @brief LCM 관련 정보
 *
 * LCM 정보파일로부터 읽어들인 정보가 저장된다.
 */
struct Dot2LCMInfo
{
  struct {
    char *rca_cert_file_path; ///< RootCA TLS 인증서파일 저장 경로 (예: "/etc/ssl/certs/4932ca72.0")
  } tls;

  struct {
    char *acp_url; ///< 응용인증서발급요청 URL (예: "https://ra.scms.tta.or.kr:8892/provision-application-certificate")
    char *pcp_url; ///< 익명인증서발급요청 URL (예: "https://ra.scms.tta.or.kr:8892/provision-pseudonym-certificate-batch")
    char *icp_url; ///< 익명인증서발급요청 URL (예: "https://ra.scms.tta.or.kr:8892/provision-identity-certificate")
    char *lpf_url; ///< LPF 요청 URL (예: "https://ra.scms.tta.or.kr:8892/download/policy/local")
    char *lccf_url; ///< LCCF 요청 URL (예: "https://ra.scms.tta.or.kr:8892/download/local-certificate-chain")
    char *crl_url; ///< CRL 요청 URL (예: https://ra.scms.tta.or.kr:8894/download-crl)
  } ra;

  char *tmp_zip_file_path; ///< 동작 중 다운로드한 ZIP 파일이 임시 저장될 파일 경로 (예: "down.zip", "/tmp/down.zip")

#ifdef _UNIT_TEST_
  /*
   * 단위테스트 시 테스트벡터를 설정하기 위한 정보
   */
  struct {
    struct {
      struct {
        struct Dot2ECKeyPairOcts verify_key;
        struct Dot2ECKeyPairOcts encryption_key;
        uint8_t provisioning_req[kDot2SPDUSize_Max];
        size_t provisioning_req_size;
        uint8_t provisioning_req_h8[8];
        bool down_resp_replace;
        uint8_t down_resp[500];
        size_t down_resp_size;
      } tv; ///< 테스트벡터 정보 (테스트코드에 의해 세팅된다)
      struct {
        uint8_t provisioning_req[kDot2SPDUSize_Max];
        size_t provisioning_req_size;
        struct Dot2SHA256 provisioning_req_h;
        uint8_t down_req_filename[100];
        uint8_t down_resp[500];
        size_t down_resp_size;
      } res; ///< 수행결과가 저장되는 정보 (실행결과가 저장된다)
    } app_cert;

    struct {
      struct {
        struct Dot2ECKeyPairOcts verify_key;
        struct Dot2ECKeyPairOcts encryption_key;
        struct Dot2AESKey verify_exp_key;
        struct Dot2AESKey encryption_exp_key;
        uint8_t prov_req_h8[8];
        unsigned int i_period;
        bool down_resp_replace;
        uint8_t down_resp[500];
        size_t down_resp_size;
      } tv; ///< 테스트벡터 정보 (테스트코드에 의해 세팅된다)
      struct {
        char down_req_filename[100];
        uint8_t down_resp[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD][500];
        size_t down_resp_size[DOT2_DEFAULT_P_CERTS_PER_I_PERIOD];
      } res; ///< 수행결과가 저장되는 정보 (실행결과가 저장된다)
    } pseudonym_cert;

    struct {
      struct {
        struct Dot2ECKeyPairOcts verify_key;
        struct Dot2ECKeyPairOcts encryption_key;
        struct Dot2AESKey verify_exp_key;
        struct Dot2AESKey encryption_exp_key;
        uint8_t prov_req_h8[8];
        unsigned int i_period;
        bool down_resp_replace;
        uint8_t down_resp[500];
        size_t down_resp_size;
      } tv; ///< 테스트벡터 정보 (테스트코드에 의해 세팅된다)
      struct {
        char down_req_filename[100];
        uint8_t down_resp[500];
        size_t down_resp_size;
      } res; ///< 수행결과가 저장되는 정보 (실행결과가 저장된다)
    } id_cert;

    struct {
      struct {
        char req_filename[50];
      } res; ///< 수행결과가 저장되는 정보 (실행결과가 저장된다)
    } down_info; ///< 인증서다운로드일정정보 관련

    struct {
      uint8_t resp[10000];
      size_t resp_size;
      char resp_hdr[9][100];
      unsigned int resp_hdr_num;
#define CURLcode int // from curl.h
#define CURLE_OK (0) // from curl.h
#define CURLE_UNSUPPORTED_PROTOCOL (1)
      CURLcode res;
      long http_code;
    } https_resp_tv; ///< HTTPS 응답 테스트벡터 (테스트코드에 의해 세팅된다)

    struct {
      bool ignore_valid_period; ///< CRL 유효기간 무시 여부
    } crl; ///< CRL 테스트용 정보 (테스트코드에 의해 세팅된다)
  } test;
#endif
};


/**
 * @brief ZIP 파일 내에 저장된 인증서다운로드응답문 바이트열
 */
struct Dot2UnzipCertDownloadResponse
{
  uint8_t *octs;
  size_t len;
};


/**
 * @brief 해시 기반 인증서폐기정보 엔트리
 *
 * 각 엔트리는 하나의 인증서에 대한 폐기정보(=H10(인증서))를 저장한다.
 */
struct Dot2HashBasedCertRevocationEntry
{
  uint8_t h10[10]; /// 폐기된 인증서의 H10 값
  TAILQ_ENTRY(Dot2HashBasedCertRevocationEntry) entries;
};
TAILQ_HEAD(Dot2HashBasedCertRevocationEntryHead, Dot2HashBasedCertRevocationEntry);


/**
 * @brief 해시 기반 인증서 폐기정보(=H10(인증서)) 중 H1 값(=마지막 바이트)이 동일한 인증서폐기정보끼리 저장되는 리스트
 */
struct Dot2HashBasedCRLH1List
{
  Dot2CertRevocationEntryNum entry_num; ///< 리스트 내 저장된 인증서폐기정보 엔트리 개수
  Dot2CertRevocationEntryNum max_entry_num; ///< 리스트 내 저장가능한 인증서폐기정보 엔트리 최대 개수 (초기화 시 설정됨)
  struct Dot2HashBasedCertRevocationEntryHead head; ///< 인증서폐기정보 엔트리들에 대한 리스트
};


/**
 * @brief 해시 기반 CRL 저장 테이블
 */
struct Dot2HashBasedCRLTable
{
#define HASH_CERT_REVOCATION_LIST_NUM (256)
  struct Dot2HashBasedCRLH1List list[HASH_CERT_REVOCATION_LIST_NUM]; ///< H1(인증서) 값 별 인증서폐기정보 리스트
};


/**
 * @brief LV(Linkage Value) 기반 인증서폐기정보 엔트리
 *
 * 각 엔트리는 하나의 인증서폐기정보(=LV)를 저장한다.
 */
struct Dot2LVBasedCertRevocationEntry
{
  uint8_t lv[DOT2_LINKAGE_VALUE_LEN]; /// 폐기된 인증서의 LV 값
  TAILQ_ENTRY(Dot2LVBasedCertRevocationEntry) entries;
};
TAILQ_HEAD(Dot2LVBasedCertRevocationEntryHead, Dot2LVBasedCertRevocationEntry);


/**
 * @brief LV 기반 인증서 폐기정보 중 LV 값의 마지막 바이트가 동일한 인증서폐기정보끼리 저장되는 리스트
 */
struct Dot2LVBasedCertRevocationList
{
  Dot2CertRevocationEntryNum entry_num; ///< 리스트 내 저장된 인증서폐기정보 엔트리 개수
  Dot2CertRevocationEntryNum max_entry_num; ///< 리스트 내 저장가능한 인증서폐기정보 엔트리 최대 개수 (초기화 시 설정됨)
  struct Dot2LVBasedCertRevocationEntryHead head; ///< 인증서폐기정보 엔트리들에 대한 리스트
};


/**
 * @brief LV(Linkage Value) 기반 CRL 정보 엔트리
 *
 * i-period(=iCert) 값이 동일한 인증서에 대한 폐기정보들이 저장되는 엔트리
 */
struct Dot2LVBasedCRLEntry
{
  uint32_t i; ///< 인증서 i-period 값
#define LV_CERT_REVOCATION_LIST_NUM (256)
  struct Dot2LVBasedCertRevocationList list[LV_CERT_REVOCATION_LIST_NUM]; ///< LV 값의 마지막 바이트 값 별 인증서폐기정보리스트
  TAILQ_ENTRY(Dot2LVBasedCRLEntry) entries;
};
TAILQ_HEAD(Dot2LVBasedCRLEntryHead, Dot2LVBasedCRLEntry);


/**
 * @brief LV(Linkage Value) 기반 CRL 저장 테이블
 */
struct Dot2LVBasedCRLTable
{
  Dot2LVBasedCRLEntryNum entry_num; ///< 리스트 내 저장된 CRL 정보 엔트리 개수
  Dot2LVBasedCRLEntryNum max_entry_num; ///< 리스트 내 저장가능한 CRL 정보 엔트리 최대 개수 (초기화 시 설정됨)
  struct Dot2LVBasedCRLEntryHead head; ///< CRL 정보 엔트리들에 대한 리스트
};


/**
 * @brief CRL(인증서폐기리스트) 테이블
 */
struct Dot2CRLTable
{
  struct Dot2HashBasedCRLTable hash; ///< 해시 기반 인증서폐기정보 저장 테이블
  struct Dot2LVBasedCRLTable lv; ///< LV 기반 인증서폐기정보 저장 테이블
};


#endif //V2X_SW_DOT2_LCM_H
