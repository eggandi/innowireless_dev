/** 
 * @file
 * @brief cmhf 유틸리티 메인 헤더 파일
 * @date 2020-05-23
 * @author gyun
 */


#ifndef V2X_SW_CMHF_H
#define V2X_SW_CMHF_H


// 시스템 헤더 파일
#include <stddef.h>
#include <stdint.h>

// 라이브러리 헤더 파일
#include "dot2-2016/dot2.h"


/// 문자열 최대길이
#define MAXLINE 255


/**
 * @brief cmhf 유틸리티 동작 유형
 */
enum eCMHFOperationType
{
  kCMHFOperation_MakeApp, ///< Application 인증서 기반 cmhf 파일 생성 동작
  kCMHFOperation_MakePseudonym, ///< Pseudonym 인증서 기반 cmhf 파일 생성 동작
  kCMHFOperation_MakeId, ///< Identification 인증서 기반 cmhf 파일 생성 동작
};
typedef unsigned int CMHFOperationType; ///< @ref eCMHFOperationType


/*
 * 프로그램 내에서 사용되는 전역 변수 및 함수
 */
extern CMHFOperationType g_op;
extern bool g_dbg;
extern char g_cmhf_file_path[MAXLINE];
extern char g_issuer_file_path[MAXLINE];
extern char g_my_cert_file_path[MAXLINE];
extern char g_recon_priv_file_path[MAXLINE];
extern char g_init_priv_file_path[MAXLINE];
extern char g_my_certs_dir[MAXLINE];
extern char g_seed_priv_file_path[MAXLINE];
extern char g_exp_key_file_path[MAXLINE];
extern uint8_t g_issuer[kDot2CertSize_Max];
extern size_t g_issuer_size;
extern uint8_t g_my_cert[kDot2CertSize_Max];
extern size_t g_my_cert_size;
extern uint8_t g_recon_priv[DOT2_EC_256_KEY_LEN];
extern uint8_t g_init_priv[DOT2_EC_256_KEY_LEN];
extern uint8_t g_exp_key[DOT2_AES_128_LEN];
extern uint8_t g_seed_priv[DOT2_EC_256_KEY_LEN];


int CMHF_ImportCertFile(const char *file_path, uint8_t *cert_buf, size_t cert_buf_size);
int CMHF_ImportPrivateKey(const char *file_path, uint8_t *priv_key);
int CMHF_ImportExpansionKey(const char *file_path, uint8_t *exp_key);
int CMHF_ImportIssuerCerts(void);
int CMHF_MakeApplicationCMHF(void);
int CMHF_MakePseudonymCMHF(void);
int CMHF_MakeIdentificationCMHF(void);
void CMHF_PrintOctets(const char *desc, const uint8_t *octets, size_t len);

#endif //V2X_SW_CMHF_H
