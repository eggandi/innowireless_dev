/** 
 * @file
 * @brief
 * @date 2020-02-19
 * @author gyun
 */


#ifndef V2X_SW_DOT2_FFASN1C_H
#define V2X_SW_DOT2_FFASN1C_H


// 시스템 헤더
#include <stdint.h>

// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-api-params.h"
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal-types.h"
#include "certificate/cert-info/dot2-scc-cert-info.h"


#ifdef  __cplusplus
extern "C" {
#endif


// dot2-ffasn1c-encode.c
int INTERNAL dot2_ffasn1c_EncodeUnsecuredIeee1609Dot2Data(const uint8_t *payload, Dot2SPDUSize payload_size, uint8_t **spdu);

// dot2-ffasn1c-encode-spdu.c
int INTERNAL dot2_ffasn1c_EncodeSignedIeee1609Dot2Data(const uint8_t *payload, Dot2SPDUSize payload_size, Dot2PSID psid, bool gen_time_hdr, Dot2Time64 gen_time, bool exp_time_hdr, Dot2Time64 exp_time, bool gen_location_hdr, const struct Dot2ThreeDLocation *gen_location, Dot2SignerIdType signer_id_type, const struct Dot2SHA256 *signer_h, EC_KEY *eck_priv_key, dot2Certificate *asn1_signer, Dot2ECPointForm sign_form, uint8_t **spdu);

// dot2-ffasn1c-parse.c
int INTERNAL dot2_ffasn1c_ParseEccP256CurvePoint(const dot2EccP256CurvePoint *from, struct Dot2ECPoint *to);
int INTERNAL dot2_ffasn1c_ParseSignature(const dot2Signature *from, struct Dot2Signature *to);

// dot2-ffasn1c-parse-cert.c
Dot2SCCCertType INTERNAL dot2_ffasn1c_CheckSCCCertTypeWithSSP(dot2ServiceSpecificPermissions *asn1_ssp);
Dot2SCCCertType INTERNAL dot2_ffasn1c_ParseSCCCertType(dot2Certificate *asn1_cert);
int INTERNAL dot2_ffasn1c_ParseCertCommonContents(const dot2Certificate *asn1_cert, struct Dot2CertCommonContents *contents);

// dot2-ffasn1c-parse-ee-cert.c
dot2Certificate INTERNAL * dot2_ffasn1c_ParseEECertContents_1(const uint8_t *cert, Dot2CertSize cert_size, struct Dot2EECertContents *contents, int *err);
int INTERNAL dot2_ffasn1c_ParseEECertContents_2(const dot2Certificate *asn1_cert, struct Dot2EECertContents *contents);
int INTERNAL dot2_ffasn1c_ParseCertAppPermissions(const dot2Certificate *asn1_cert, struct Dot2EECertPermissions *to);
int INTERNAL dot2_ffasn1c_ParseCertReqPermissions(const dot2Certificate *asn1_cert, struct Dot2EECertPermissions *to);

// dot2-ffasn1c-parse-scc-cert.c
int INTERNAL dot2_ffasn1c_ParseSCCCertContents(const uint8_t *cert, Dot2CertSize cert_size, struct Dot2SCCCertContents *contents, struct Dot2Signature *sign);

// dot2-ffasn1c-parse-spdu.c
int INTERNAL dot2_ffasn1c_ParseToBeSignedData(const dot2ToBeSignedData *asn1_data, struct V2XPacketParseData *parsed);

// dot2-ffasn1c-process-spdu.c
int INTERNAL dot2_ffasn1c_ParseAndProcessSPDU(struct Dot2SPDUProcessWork *work);;


#ifdef _SUPPORT_SCMS_

// dot2-ffasn1c-lcm.c
int INTERNAL dot2_ffasn1c_FillEncryptedData(uint8_t *data, size_t data_size, const struct Dot2SHA256 *key_input_h, struct Dot2ECPublicKey *pubkey_r, dot2EncryptedData *asn1_enc);
int INTERNAL dot2_ffasn1c_FillSignedCertificateReqeust_Signer(dot2Certificate *asn1_ec, dot2SignerIdentifier *asn1_signer);
int INTERNAL dot2_ffasn1c_FillSignedCertificateReqeust_Signature(const struct Dot2SHA256 *ec_h, EC_KEY *eck_ec_priv_key, dot2ScopedCertificateRequest *asn1_tbs, dot2Signature *asn1_sign);

// dot2-ffasn1c-lcm-crl.c
int INTERNAL dot2_ffasn1c_ProcessCRL(const uint8_t *crl, Dot2CRLSize crl_size);

// dot2-ffasn1c-lcm-app-cert-provisioning.c
int INTERNAL dot2_ffasn1c_FillEeRaAppCertProvisioningRequest(Dot2Time32 current_time, Dot2Time32 start_time, const struct Dot2ECPublicKey *verify_pub_key, const struct Dot2ECPublicKey *cert_enc_pub_key, dot2EeRaAppCertProvisioningRequest *asn1_req);

// dot2-ffasn1c-lcm-download.c
uint8_t INTERNAL *dot2_ffasn1c_ConstructCertDownloadRequest(const char *req_filename, struct Dot2CertRequestInfo *cr_info, int *ret);
int INTERNAL dot2_ffasn1c_ParseSignedEncryptedCertificateResponse(Dot2CMHType cert_type, const uint8_t *resp, Dot2SPDUSize resp_size, struct Dot2ECPrivateKey *cert_enc_priv_key, struct Dot2AESKey *cert_enc_exp_key, Dot2IPeriod i_period, Dot2CertJvalue j_value, struct Dot2Signature *resp_sign, struct Dot2SHA256 *resp_tbs_h, struct Dot2ECPrivateKey *recon_priv, struct Dot2Cert *cert);
int INTERNAL dot2_ffasn1c_ParseCertDownloadInfoResponse(const uint8_t *resp, size_t resp_size, Dot2Time32 *cert_dl_time);

// dot2-ffasn1c-lcm-ecrequest.c
uint8_t INTERNAL * dot2_ffasn1c_ConstructECRequest(struct Dot2ECRequestConstructParams *params, struct Dot2ECKeyPair *tmp_key_pair, int *ret);

// dot2-ffasn1c-lcm-ecresponse.c
int INTERNAL dot2_ffasn1c_ParseECResponse(const uint8_t *ec_resp, size_t ec_resp_size, uint8_t *ec_req_h8);

// dot2-ffasn1c-lcm-id-cert-provisioning.c
int INTERNAL dot2_ffasn1c_FillEeRaIdCertProvisioningRequest(Dot2Time32 current_time, Dot2Time32 start_time, const struct Dot2ECPublicKey *verify_pub_key, const struct Dot2ECPublicKey *cert_enc_pub_key, const struct Dot2AESKey *verify_exp_key, const struct Dot2AESKey *cert_enc_exp_key, dot2EeRaIdCertProvisioningRequest *asn1_req);

// dot2-ffasn1c-lcm-lccf.c
int INTERNAL dot2_ffasn1c_ParseLCCF(const uint8_t *lccf, Dot2LCCFSize lccf_size, uint8_t **rca_cert, Dot2CertSize *rca_cert_size, uint8_t **ica_cert, Dot2CertSize *ica_cert_size, uint8_t **pca_cert, Dot2CertSize *pca_cert_size, uint8_t **crlg_cert, Dot2CertSize *crlg_cert_size);

// dot2-ffasn1c-lcm-provisioning.c
uint8_t INTERNAL * dot2_ffasn1c_ConstructSecuredCertProvisioningRequest(Dot2CMHType cert_type, Dot2Time32 current_time, Dot2Time32 start_time, const struct Dot2ECPublicKey *verify_pub_key, const struct Dot2ECPublicKey *cert_enc_pub_key, const struct Dot2AESKey *verify_exp_key, const struct Dot2AESKey *cert_enc_exp_key, struct Dot2CertRequestInfo *cr_info, int *ret);
int INTERNAL dot2_ffasn1c_ParseSignedCertProvisioningAck(Dot2CMHType cert_type, const uint8_t *ack, Dot2SPDUSize ack_size, uint8_t *req_h8, Dot2Time32 *cert_dl_time, char **cert_dl_url, uint8_t **tbs, Dot2SPDUSize *tbs_size, struct Dot2Signature *sign);

// dot2-ffasn1c-lcm-pseudonym-cert-provisioning.c
int INTERNAL dot2_ffasn1c_FillEeRaPseudonymCertProvisioningRequest(Dot2Time32 current_time, Dot2Time32 start_time, const struct Dot2ECPublicKey *verify_pub_key, const struct Dot2ECPublicKey *cert_enc_pub_key, const struct Dot2AESKey *verify_exp_key, const struct Dot2AESKey *cert_enc_exp_key, dot2EeRaPseudonymCertProvisioningRequest *asn1_req);

#endif

#ifdef  __cplusplus
}
#endif

#endif //V2X_SW_DOT2_FFASN1C_H
