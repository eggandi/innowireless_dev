/** 
 * @file
 * @brief libdot2 라이브러리 내부에서 사용되는 내부 함수들의 원형을 정의한 파일
 * @date 2020-02-18
 * @author gyun
 */

#ifndef V2X_SW_DOT2_INTERNAL_FUNCS_H
#define V2X_SW_DOT2_INTERNAL_FUNCS_H


// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-defines.h"
#include "dot2-internal-types.h"
#include "certificate/cert-info/dot2-scc-cert-info.h"
#include "certificate/cert-info/dot2-ee-cert-cache.h"
#include "certificate/cmh/dot2-cmh.h"
#include "certificate/cmhf/dot2-cmhf.h"
#include "sec-profile/dot2-sec-profile.h"
#include "spdu/dot2-spdu.h"
#ifdef _SUPPORT_SCMS_
#include "lcm/dot2-lcm.h"
#endif


#ifdef __cplusplus
extern "C" { // 단위테스트에서 아래 함수들을 호출하기 위해 정의
#endif


// certificate/cert-info/dot2-ee-cert-cache.c
void INTERNAL dot2_InitEECertCacheH1List(struct Dot2EECertCacheH1List *list);
void INTERNAL dot2_InitEECertCacheTable(void);
void INTERNAL dot2_ReleaseEECertCacheH1List(struct Dot2EECertCacheH1List *list);
void INTERNAL dot2_ReleaseEECertCacheTable(void);
int INTERNAL dot2_PushEECertCacheEntry(struct Dot2EECertCacheEntry *entry);
int INTERNAL dot2_ConstructEECertChain(struct Dot2EECertCacheEntry *entry);
void INTERNAL dot2_RemoveExpiredEECertCache(Dot2Time64 exp);


// certificate/cert-info/dot2-scc-cert-info.c
void INTERNAL dot2_InitSCCCertInfoTable(void);
void INTERNAL dot2_ReleaseSCCCertInfoTable(void);
void INTERNAL dot2_ClearSCCCertContents(struct Dot2SCCCertContents *contents);
void INTERNAL dot2_ClearSCCCertInfoEntry(struct Dot2SCCCertInfoEntry *entry);
struct Dot2SCCCertInfoEntry INTERNAL * dot2_AllocateSCCCertInfoEntry(const uint8_t *cert, Dot2CertSize cert_size);
int INTERNAL dot2_GetCertContentsAndSignatureFromSCCCert(const uint8_t *cert, Dot2CertSize cert_size, struct Dot2SCCCertContents *info, struct Dot2Signature *sign);
void INTERNAL dot2_InitSCCCertInfoList(void);
void INTERNAL dot2_ReleaseSCCCertInfoList(void);
struct Dot2SCCCertInfoEntry INTERNAL * dot2_FindSCCCertWithHashedID8(const uint8_t *h8);
struct Dot2SCCCertInfoEntry INTERNAL * dot2_AddSCCCert(const uint8_t *cert, Dot2CertSize cert_size, int *err);
void INTERNAL dot2_RemoveExpiredSCCCert(Dot2Time64 exp);

// certificate/cmh/dot2-cmh.c
void INTERNAL dot2_InitCMHTable(void);
void INTERNAL dot2_ReleaseCMHTable(void);
int INTERNAL dot2_GetAvailableCMHInfo(Dot2PSID psid, Dot2Time64 now, unsigned int interval, bool cmh_change, struct Dot2SHA256 *cert_h, EC_KEY **eck_priv_key, void **asn1_cert, bool *cmh_changed, bool *cmh_expiry);
void INTERNAL dot2_RemoveExpiredCMH(Dot2Time64 exp);

// certificate/cmh/dot2-cmh-rotate.c
void INTERNAL dot2_InitRotateCMHSetList(struct Dot2RotateCMHSetList *list);
void INTERNAL dot2_ReleaseRotateCMHSetList(struct Dot2RotateCMHSetList *list);
void INTERNAL dot2_ClearRotateCMHSetEntry(struct Dot2RotateCMHSetEntry *entry);
void INTERNAL dot2_ReleaseRotateCMHSetEntry(struct Dot2RotateCMHSetEntry *entry);
void INTERNAL dot2_ClearRotateCMHSetCommonInfo(struct Dot2RotateCMHSetCommonInfo *info);
void INTERNAL dot2_ClearRotateCMHInfo(struct Dot2RotateCMHInfo *info);
void INTERNAL dot2_ClearRotateCMHIndividualInfo(struct Dot2RotateCMHIndividualInfo *info);
int INTERNAL dot2_PushRotateCMHSetEntry(Dot2CMHType cmh_type, struct Dot2RotateCMHSetEntry *entry);
int INTERNAL dot2_GetAvailableRotateCMHInfo(Dot2PSID psid, Dot2Time64 now, unsigned int interval, bool cmh_change, struct Dot2SHA256 *cert_h, EC_KEY **eck_priv_key, void **asn1_cert, bool *cmh_changed, bool *cmh_expiry);
void INTERNAL dot2_RemoveExpiredRotateCMHSet(Dot2Time64 exp, struct Dot2RotateCMHSetList *list);

// certificate/cmh/dot2-cmh-sequential.c
void INTERNAL dot2_InitSequentialCMHList(struct Dot2SequentialCMHList *list);
void INTERNAL dot2_ReleaseSequentialCMHList(struct Dot2SequentialCMHList *list);
void INTERNAL dot2_ClearSequentialCMHEntry(struct Dot2SequentialCMHEntry *entry);
void INTERNAL dot2_ReleaseSequentialCMHEntry(struct Dot2SequentialCMHEntry *entry);
void INTERNAL dot2_ClearSequentialCMHInfo(struct Dot2SequentialCMHInfo *info);
int INTERNAL dot2_PushSequentialCMHEntry(Dot2CMHType cmh_type, struct Dot2SequentialCMHEntry *entry);
struct Dot2SequentialCMHEntry INTERNAL * dot2_GetCurrentlyAvailableSequentialCMHEntry(struct Dot2SequentialCMHList *list, Dot2Time64 now);
int INTERNAL dot2_GetAvailableSequentialCMHInfo(Dot2PSID psid, Dot2Time64 now, struct Dot2SHA256 *cert_h, EC_KEY **eck_priv_key, void **asn1_cert);
void INTERNAL dot2_RemoveExpiredSequentialCMH(Dot2Time64 current, struct Dot2SequentialCMHList *list);

// certificate/cmhf/dot2-cmhf-load.c
int INTERNAL dot2_LoadCMHF(const uint8_t *cmhf, Dot2CMHFSize cmhf_size);
int INTERNAL dot2_CheckCMHFCommonInfo(struct Dot2CMHFCommonInfo *info);
int INTERNAL dot2_CheckCMHFIndividualInfo(struct Dot2CMHFIndividualInfo *info);
int INTERNAL dot2_LoadCMHFFile(const char *file_path);

// certificate/cmhf/dot2-cmhf-load-rotate.c
int INTERNAL dot2_AddRotateCMHfromCMHF(Dot2CMHType cmh_type, const uint8_t *cmhf, int cmhf_size);

// certificate/cmhf/dot2-cmhf-load-sequential.c
int INTERNAL dot2_AddSequentialCMHfromCMHF(Dot2CMHType cmh_type, const uint8_t *cmhf, int cmhf_size);

// certificate/cmhf/dot2-cmhf-make.c
int INTERNAL dot2_FillCMHFCommonInfo(Dot2CMHType cmh_type, const struct Dot2SHA256 *issuer_h, const struct Dot2EECertContents *contents, int buf_size, uint8_t *ptr);
int INTERNAL dot2_FillCMHFIndividualInfo(const struct Dot2Cert *cert, const struct Dot2SHA256 *cert_h, const struct Dot2ECPrivateKey *priv_key, const struct Dot2EECertContents *contents, int buf_size, uint8_t *ptr);
char INTERNAL * dot2_MakeCMHFName(Dot2CMHType cmh_type, Dot2PrivKeyType priv_key_type, const struct Dot2EECertContents *contents, int *err);

// certificate/cmhf/dot2-cmhf-make-sequential.c
int INTERNAL dot2_MakeSequentialCMHFforImplicitCert_1(Dot2CMHType cmh_type, const struct Dot2ECPrivateKey *init_priv_key, const struct Dot2ECPrivateKey *recon_priv, const struct Dot2Cert *cert, const struct Dot2Cert *issuer, char **cmhf_name, uint8_t **cmhf, Dot2CMHFSize *cmhf_size, struct Dot2ECPrivateKey *priv_key);
int INTERNAL dot2_MakeSequentialCMHFforImplicitCert_2(Dot2CMHType cmh_type, const struct Dot2ECPrivateKey *init_priv_key, const struct Dot2ECPrivateKey *recon_priv, const struct Dot2Cert *cert, const struct Dot2SHA256 *issuer_h, const struct Dot2ECPublicKey *issuer_pub_key, char **cmhf_name, uint8_t **cmhf, Dot2CMHFSize *cmhf_size, struct Dot2ECPrivateKey *priv_key);

// certificate/cmhf/dot2-cmhf-make-rotate.c
int INTERNAL dot2_MakeRotateCMHFforImplicitCert_1(Dot2CMHType cmh_type, uint32_t i, Dot2CertJvalue j_max, const struct Dot2AESKey *exp_key, const struct Dot2ECPrivateKey *seed_priv, const struct Dot2Cert *certs, const struct Dot2ECPrivateKey *recon_privs, const struct Dot2Cert *issuer, char **cmhf_name, uint8_t **cmhf, Dot2CMHFSize *cmhf_size, struct Dot2ECPrivateKey *priv_keys);
int INTERNAL dot2_MakeRotateCMHFforImplicitCert_2(Dot2CMHType cmh_type, uint32_t i, Dot2CertJvalue j_max, const struct Dot2AESKey *exp_key, const struct Dot2ECPrivateKey *seed_priv, const struct Dot2Cert *certs, const struct Dot2ECPrivateKey *recon_privs, const struct Dot2SHA256 *issuer_h, const struct Dot2ECPublicKey *issuer_pub_key, char **cmhf_name, uint8_t **cmhf, Dot2CMHFSize *cmhf_size, struct Dot2ECPrivateKey *priv_keys);
int INTERNAL dot2_MakeRotateCMHFforImplicitCert_3(Dot2CMHType cmh_type, uint32_t i, Dot2CertJvalue j_max, const struct Dot2ECPrivateKey *priv_keys, const struct Dot2Cert *certs, const struct Dot2EECertContents *contents, const struct Dot2SHA256 *issuer_h, char **cmhf_name, uint8_t **cmhf, Dot2CMHFSize *cmhf_size);

// sec-executer/dot2-sec-executer.c
int INTERNAL dot2_InitSecExecuter(Dot2SigningParamsPrecomputeInterval interval);
void INTERNAL dot2_ReleaseSecExecuter(void);

// sec-profile/dot2-sec-profile.c
void INTERNAL dot2_InitSecProfileTable(void);
void INTERNAL dot2_FlushSecProfileTable(void);
void INTERNAL dot2_ReleaseSecProfileTable(void);
int INTERNAL dot2_CheckSecProfile(const struct Dot2SecProfile *profile);
int INTERNAL dot2_AddSecProfile(const struct Dot2SecProfile *profile);
Dot2SignerIdType INTERNAL dot2_SelectSignerIdType(Dot2Time64 now, struct Dot2SecProfileEntry *entry);

// sec-profile/dot2-sec-profile-replay.c
void INTERNAL dot2_InitSecProfileReplayCheckList(struct Dot2SecProfileReplayCheckList *list);
void INTERNAL dot2_FlushSecProfileReplayCheckList(struct Dot2SecProfileReplayCheckList *list);
int INTERNAL dot2_AddSecProfileReplayCheckEntry(struct Dot2SecProfileReplayCheckList *list, Dot2Time64 current_time, Dot2Time64 spdu_gen_time, struct Dot2Signature *spdu_sign);
bool INTERNAL dot2_CheckIdenticalSecProfileReplayCheckEntry(struct Dot2SecProfileReplayCheckEntry *entry, Dot2Time64 spdu_gen_time, struct Dot2Signature *spdu_sign);
struct Dot2SecProfileReplayCheckEntry INTERNAL * dot2_FindIdenticalSPDUInSecProfileReplayCheckList(struct Dot2SecProfileReplayCheckList *list, Dot2Time64 current_time, Dot2Time64 spdu_gen_time, struct Dot2Signature *spdu_sign, Dot2Time64 valid_period);

// signature/dot2-sign-verify.c
int INTERNAL dot2_VerifySPDUSignature(struct Dot2SPDUProcessWork *work);

// spdu/dot2-spdu-consistency.c
int INTERNAL dot2_CheckSPDUConsistency(struct V2XPacketParseData *parsed, struct Dot2SecProfile *sec_profile, struct Dot2EECertCacheEntry *signer_entry);

// spdu/dot2-spdu-construct.c
int INTERNAL dot2_ConstructSignedSPDU(const uint8_t *payload, Dot2SPDUSize payload_size, Dot2PSID psid, Dot2Time64 gen_time, Dot2SignerIdType signer_id_type, const struct Dot2ThreeDLocation *gen_location, bool cmh_change, uint8_t **spdu, bool *cmh_expiry);

// spdu/dot2-spdu-process.c
int INTERNAL dot2_InitSPDUProcessFunction(struct Dot2SPDUProcess *spdu_process);
void INTERNAL dot2_ReleaseSPDUProcessFunction(struct Dot2SPDUProcess *spdu_process);
int INTERNAL dot2_ProcessSPDUConsistencyAndRelevanceCheck(struct Dot2SPDUProcessWork *work, struct Dot2EECertCacheEntry *signer_entry);

// spdu/dot2-spdu-process-work.c
void INTERNAL dot2_InitSPDUProcessWorkQueue(struct Dot2SPDUProcessWorkQueue *q);
void INTERNAL dot2_FlushSPDUProcessWorkQueue(struct Dot2SPDUProcessWorkQueue *q);
int INTERNAL dot2_AddNewSPDUProcessWorkRequest(uint8_t *spdu, Dot2SPDUSize spdu_size, struct Dot2SPDUProcessParams *params, struct V2XPacketParseData *parsed);
void INTERNAL dot2_ProcessSPDUProcessWorkWait(int result, struct Dot2SPDUProcessWork *work);
int INTERNAL dot2_ProcessSPDUProcessWork_SignVerificationResult(struct Dot2SPDUProcessWork *work);
void INTERNAL * dot2_SPDUProcessWorkRequestHandleThread(void *arg);
void INTERNAL * dot2_SPDUProcessWorkWaitHandleThread(void *arg);
void INTERNAL * dot2_SPDUProcessWorkResultHandleThread(void *arg);

// dot2-spdu-relevance.c
int INTERNAL dot2_CheckSPDURelevance(struct Dot2SPDUProcessWorkData *work_data, struct Dot2SecProfileEntry *sec_profile_entry, struct Dot2EECertCacheEntry *signer_entry);



// dot2.c
int INTERNAL dot2_InitDot2(Dot2LogLevel log_level, Dot2SigningParamsPrecomputeInterval interval, const char *rng_dev, Dot2LeapSeconds leap_secs);
void INTERNAL dot2_ReleaseDot2(void);

// dot2-file.c
int INTERNAL dot2_ImportFile(const char *file_path, uint8_t *buf, size_t min_size, size_t max_size);
int INTERNAL dot2_ImportFile_2(const char *file_path, uint8_t **buf, size_t min_size, size_t max_size);
int INTERNAL dot2_ExportFile(const char *file_path, const uint8_t *octs, size_t len);

// dot2-log.c
void INTERNAL dot2_PrintLog(const char *func, const char *format, ...);

// dot2-random.c
int INTERNAL dot2_SetRandomNumberGenerator(const char *rng_dev);
uint8_t INTERNAL dot2_GetRandomOct(const char *rng_dev);


#ifdef _SUPPORT_SCMS_

// lcm/dot2-lcm.c
int INTERNAL dot2_ConfigLCM(Dot2LCMConfigType type, const char *cfg_str);
int INTERNAL dot2_GetCertRequestInfo(Dot2Time32 current_time, struct Dot2CertRequestInfo *info);
void INTERNAL dot2_ClearCertRequestInfo(struct Dot2CertRequestInfo *info);
int INTERNAL dot2_UnzipSingleCertDownloadResponseFile(const char *tmp_path, const uint8_t *zip_octs, size_t zip_octs_size, struct Dot2UnzipCertDownloadResponse *unzip_resp);
int INTERNAL dot2_UnzipMultipleCertDownloadResponseFiles(const char *tmp_path, const uint8_t *zip_octs, size_t zip_octs_size, Dot2IPeriod i_period, unsigned int response_file_num, struct Dot2UnzipCertDownloadResponse *unzip_resps);

// lcm/dot2-lcm-crl.c
void INTERNAL dot2_InitCRLTable(void);
void INTERNAL dot2_ReleaseCRLTable(void);
bool INTERNAL dot2_CheckCertRevocation(struct Dot2CertId *cert_id, const uint8_t *h10);
int INTERNAL dot2_DownloadCRL(uint8_t **crl);

// lcm/dot2-lcm-crl-hash.c
void INTERNAL dot2_InitHashBasedCRLTable(struct Dot2HashBasedCRLTable *table);
void INTERNAL dot2_FlushHashBasedCRLTable(struct Dot2HashBasedCRLTable *table);
struct Dot2HashBasedCertRevocationEntry INTERNAL * dot2_FindHashBasedCertRevocationEntry(struct Dot2HashBasedCRLTable *table, const uint8_t *h10);
int INTERNAL dot2_AddHashBasedCertRevocationEntry(const uint8_t *h10);

// lcm/dot2-lcm-crl-lv.c
void INTERNAL dot2_InitLVBasedCRLTable(struct Dot2LVBasedCRLTable *table);
void INTERNAL dot2_FlushLVBasedCRLTable(struct Dot2LVBasedCRLTable *table);
struct Dot2LVBasedCertRevocationEntry INTERNAL * dot2_FindLVBasedCertRevocationEntry_2(struct Dot2LVBasedCRLTable *table, uint32_t i_period, const uint8_t *lv);
int INTERNAL dot2_AddLVBasedCertRevocationEntry(uint32_t i_period, const uint8_t *lv);

// lcm/dot2-lcm-app-cert-download.c
void INTERNAL dot2_DownloadAppCert(struct Dot2AppCertDownloadRequestParams *params, struct Dot2AppCertDownloadResult *res);

// lcm/dot2-lcm-app-cert-provisioning.c
void INTERNAL dot2_RequestAppCertProvisioning(struct Dot2CertProvisioningRequestParams *params, struct Dot2AppCertProvisioningRequestResult *res);

// lcm/dot2-lcm-download.c
int INTERNAL dot2_ProcessCertDownloadResponse(Dot2CMHType cert_type, const uint8_t *resp, Dot2SPDUSize resp_size, struct Dot2CertRequestInfo *cr_info, struct Dot2ECPrivateKey *cert_enc_priv_key, struct Dot2AESKey *cert_enc_exp_key, Dot2IPeriod i_period, Dot2CertJvalue j_value, struct Dot2ECPrivateKey *recon_priv, struct Dot2Cert *cert);
void INTERNAL dot2_DownloadCertDownloadInfo(struct Dot2CertDownloadInfoRequestParams *params, struct Dot2CertDownloadInfoDownloadResult *res);

// lcm/dot2-lcm-ecrequest.c
void INTERNAL dot2_ConstructECRequest(struct Dot2ECRequestConstructParams *params, struct Dot2ECKeyPair *tmp_key_pair, struct Dot2ECRequestConstructResult *res);

// lcm/dot2-lcm-ecresponse.c
void INTERNAL dot2_ProcessECResponse(struct Dot2ECResponseProcessParams *params, struct Dot2ECResponseProcessResult *res);

// lcm/dot2-https.c
size_t INTERNAL dot2_HTTPS_ResponseCallback(void *contents, size_t size, size_t nmemb, void *userp);
size_t INTERNAL dot2_HTTPS_ResponseHdrCallback(const char *contents, size_t size, size_t nitems, void *userdata);
void INTERNAL dot2_HTTPS_GetHTTPSConnInfo(struct Dot2HTTPSConnInfo *info);
void INTERNAL dot2_HTTPS_ClearHTTPSConnInfo(struct Dot2HTTPSConnInfo *info);

// lcm/dot2-https-post.c
int INTERNAL dot2_HTTPS_POST(const char *url, const char *rca_tls_cert_file_path, const uint8_t *req_msg, Dot2SPDUSize req_msg_size, struct Dot2HTTPSMessage *resp_msg);
int INTERNAL dot2_HTTPS_GET(const char *url, const char *rca_tls_cert_file_path, const uint8_t *hdr_msg, Dot2SPDUSize hdr_msg_size, const char *current_filename, struct Dot2HTTPSFileName *resp_filename, struct Dot2HTTPSMessage *resp_msg);

// lcm/dot2-lcm-id-cert-download.c
void INTERNAL dot2_DownloadIdCert(struct Dot2PseudonymIdCertDownloadRequestParams *params, struct Dot2IdCertDownloadResult *res);

// lcm/dot2-lcm-id-cert-provisioning.c
void INTERNAL dot2_RequestIdCertProvisioning(struct Dot2CertProvisioningRequestParams *params, struct Dot2PseudonymIdCertProvisioningRequestResult *res);

// lcm/dot2-lcm-lccf.c
int INTERNAL dot2_AddLCCFCertsToSCCList(const uint8_t *rca_cert, Dot2CertSize rca_cert_size, const uint8_t *ica_cert, Dot2CertSize ica_cert_size, const uint8_t *pca_cert, Dot2CertSize pca_cert_size, const uint8_t *crlg_cert, Dot2CertSize crlg_cert_size);
int INTERNAL dot2_DownloadLCCF(const char *current_filename, char **lccf_filename, uint8_t **lccf, Dot2LCCFSize *lccf_size);

// lcm/dot2-lcm-lpf.c
void INTERNAL dot2_DownloadLPF(const char *current_filename, struct Dot2LPFRequestResult *res);

// lcm/dot2-lcm-provisioning.c
int INTERNAL dot2_ProcessCertProvisioningAck(Dot2CMHType cert_type, const uint8_t *ack, Dot2SPDUSize ack_size, const uint8_t *req_h8, struct Dot2CertRequestInfo *cr_info, Dot2Time32 *cert_dl_time, char **cert_dl_url);

// lcm/dot2-lcm-pseudonym-cert-download.c
void INTERNAL dot2_DownloadPseudonymCert(struct Dot2PseudonymIdCertDownloadRequestParams *params, struct Dot2PseudonymCertDownloadResult *res);

// lcm/dot2-lcm-pseudonym-cert-provisioning.c
void INTERNAL dot2_RequestPseudonymCertProvisioning(struct Dot2CertProvisioningRequestParams *params, struct Dot2PseudonymIdCertProvisioningRequestResult *res);

#endif


#ifdef __cplusplus
}
#endif

#endif //V2X_SW_DOT2_INTERNAL_FUNCS_H
