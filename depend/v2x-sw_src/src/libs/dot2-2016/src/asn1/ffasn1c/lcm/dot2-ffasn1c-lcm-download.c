/** 
  * @file 
  * @brief 인증서 다운로드 관련 기능 구현
  * @date 2022-08-13 
  * @author gyun 
  */



// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 의존 헤더 파일
#include "openssl/sha.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#include "asn1/ffasn1c/dot2-ffasn1c-inline.h"
#include "encrypt/dot2-encrypt.h"


/**
 * @brief 인증서 다운로드요청문 내 eeRaAuthenticatedDownloadRequest 필드를 채운다.
 * @param[in] req_filename 다운로드 요청할 파일명
 * @param[out] asn1_req 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * timestamp는 해당 구조체의 생성 시점
 * cert_filename은 다운로드 받고자 하는 파일 명
 */
static int
dot2_ffasn1c_FilleeRaAuthenticatedDownloadRequest(const char *req_filename, dot2AuthenticatedDownloadRequest *asn1_req)
{
  Log(kDot2LogLevel_Event, "Fill eeRaAuthenticatedDownloadRequest\n");
  asn1_req->timestamp = dot2_GetCurrentTime32();
  return dot2_ffasn1c_FillASN1String((uint8_t *)req_filename, strlen(req_filename), &(asn1_req->filename));
}


/**
 * @brief 인증서 다운로드요청문 내 ScopedCertificateRequest 필드를 채운다.
 * @param[in] req_filename 다운로드 요청할 파일명
 * @param[out] asn1_req 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillScopedCertificateRequest(
  const char *req_filename,
  dot2ScopedCertificateRequest *asn1_req)
{
  Log(kDot2LogLevel_Event, "Fill ScopedCertificateRequest\n");
  asn1_req->version = KDot2ScmsPDUVersion_SCMS;
  asn1_req->content.choice = dot2ScmsPDU_1_ee_ra;
  asn1_req->content.u.ee_ra.choice = dot2EndEntityRaInterfacePDU_eeRaAuthenticatedDownloadRequest;
  dot2AuthenticatedDownloadRequest *asn1_eradr = &(asn1_req->content.u.ee_ra.u.eeRaAuthenticatedDownloadRequest);
  return dot2_ffasn1c_FilleeRaAuthenticatedDownloadRequest(req_filename, asn1_eradr);
}


/**
 * @brief 인증서다운로드요청문 내 SignedCertificateRequest 필드를 Opaque 형식으로 채운다.
 * @param[in] req_filename 다운로드 요청할 파일명
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] asn1_req 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillSignedCertificateRequest(
  const char *req_filename,
  struct Dot2CertRequestInfo *cr_info,
  dot2Opaque *asn1_req)
{
  Log(kDot2LogLevel_Event, "Fill SignedCertificateRequest\n");

  int ret = -kDot2Result_NoMemory;
  uint8_t *encoded = NULL;
  dot2SignedCertificateRequest *asn1_cr;
  asn1_cr = (dot2SignedCertificateRequest *)asn1_mallocz_value(asn1_type_dot2SignedCertificateRequest);
  if (asn1_cr) {

    // signedCertificateRequest.hashId 내용을 채운다.
    asn1_cr->hashId = dot2HashAlgorithm_sha256;

    // signedCertificateRequest.scopedCertificateRequest 내용을 채운다.
    ret = dot2_ffasn1c_FillScopedCertificateRequest(req_filename, &(asn1_cr->tbsRequest));
    if (ret < 0) {
      goto out;
    }

    // signedCertificateRequest.signer(서명자) 정보를 채운다 -> 등록인증서
    dot2_ffasn1c_FillSignedCertificateReqeust_Signer(cr_info->ec.asn1_cert, &(asn1_cr->signer));

    // signedCertificateRequest.signature(서명) 정보를 채운다.
    ret = dot2_ffasn1c_FillSignedCertificateReqeust_Signature(&(cr_info->ec.cert_h),
                                                              cr_info->ec.eck_priv_key,
                                                              &(asn1_cr->tbsRequest),
                                                              &(asn1_cr->signature));
    if (ret < 0) {
      goto out;
    }

    // signedCertificateRequest를 OER 인코딩하여 opaque 형식으로 정보를 채워 반환한다.
    ret = -kDot2Result_ASN1_EncodeSignedCertificateRequest;
    asn1_ssize_t encoded_size = asn1_oer_encode(&encoded, asn1_type_dot2SignedCertificateRequest, asn1_cr);
    if (encoded &&
        (encoded_size > 0)) {
      asn1_req->len = (size_t)encoded_size;
      asn1_req->buf = encoded;
      ret = kDot2Result_Success;
    }
  }

out:
  if (asn1_cr) { asn1_free_value(asn1_type_dot2SignedCertificateRequest, asn1_cr); }
  return ret;
}


/**
 * @brief 인증서 다운로드요청문 내 SignedAuthenticatedDownloadRequest 메시지 바이트열을 생성한다.
 * @param[in] req_filename 다운로드 요청할 파일명
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] ret 인코딩 결과가 저장될 변수 포인터. 성공 시 인코딩된 메시지의 길이, 실패 시 음수(-Dot2ResultCode)가 저장된다.
 * @return OER 인코딩된 메시지 바이트열. 동적할당된 정보이므로 사용 후 free()해 주어야 한다.
 */
static uint8_t * dot2_ffasn1c_ConstructSignedAuthenticatedDownloadRequest(
  const char *req_filename,
  struct Dot2CertRequestInfo *cr_info,
  int *ret)
{
  Log(kDot2LogLevel_Event, "Construct SignedAuthenticatedDownloadRequest\n");

  *ret = -kDot2Result_NoMemory;
  uint8_t *signed_req = NULL;
  dot2SignedAuthenticatedDownloadRequest *asn1_signed_req =
    asn1_mallocz_value(asn1_type_dot2SignedAuthenticatedDownloadRequest);
  if (asn1_signed_req) {

    asn1_signed_req->protocolVersion = DOT2_PROTOCOL_VERSION;
    asn1_signed_req->content.choice = dot2Ieee1609Dot2Content_signedCertificateRequest;

    /*
     * SignedAuthenticatedDownloadRequest 내 signedCertificateRequest 필드를 채운다.
     */
    dot2Opaque *asn1_cr = &(asn1_signed_req->content.u.signedCertificateRequest);
    *ret = dot2_ffasn1c_FillSignedCertificateRequest(req_filename, cr_info, asn1_cr);
    if (*ret < 0) {
      goto out;
    }

    /*
     * SignedAuthenticatedDownloadRequest 메시지를 OER 인코딩한다.
     */
    size_t encoded_size;
    *ret = -kDot2Result_ASN1_EncodeCertDownloadRequest;
    signed_req = dot2_ffasn1c_EncodeSecuredScmsPDU(asn1_signed_req, &encoded_size);
    if (signed_req) {
      *ret = (int)encoded_size;
    }
  }

out:
  if (asn1_signed_req) { asn1_free_value(asn1_type_dot2SignedAuthenticatedDownloadRequest, asn1_signed_req); }
  return signed_req;
}


/**
 * @brief 인증서 다운로드요청문 내 SecuredAuthenticatedDownloadRequest 필드를 채운다.
 * @param[in] signed_req SignedAuthenticatedDownloadRequest 메시지 바이트열 (암호화 대상)
 * @param[in] signed_req_size SignedAuthenticatedDownloadRequest 메시지 바이트열의 길이
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] asn1_secured_req 정보를 채울 asn.1 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillSecuredAuthenticatedDownloadRequest(
  uint8_t *signed_req,
  size_t signed_req_size,
  struct Dot2CertRequestInfo *cr_info,
  dot2SecuredAuthenticatedDownloadRequest *asn1_secured_req)
{
  Log(kDot2LogLevel_Event, "Fill SecuredAuthenticatedDownloadRequest\n");
  asn1_secured_req->protocolVersion = DOT2_PROTOCOL_VERSION;
  asn1_secured_req->content.choice = dot2Ieee1609Dot2Content_encryptedData;
  return dot2_ffasn1c_FillEncryptedData(signed_req,
                                        signed_req_size,
                                        &(cr_info->ra.cert_h),
                                        &(cr_info->ra.enc_pub_key),
                                        &(asn1_secured_req->content.u.encryptedData));
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 인증서다운로드요청문을 생성한다.
 * @param[in] req_filename 다운로드 요청할 파일명
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] ret 인코딩 결과가 저장될 변수 포인터. 성공 시 인코딩된 발급요청문의 길이, 실패 시 음수(-Dot2ResultCode)가 저장된다.
 * @return OER 인코딩된 인증서 발급요청문 바이트열. 동적할당된 정보이므로 사용 후 free()해 주어야 한다.
 */
uint8_t INTERNAL *dot2_ffasn1c_ConstructCertDownloadRequest(
  const char *req_filename,
  struct Dot2CertRequestInfo *cr_info,
  int *ret)
{
  int _ret;
  Log(kDot2LogLevel_Event, "Construct cert download request\n");

  dot2SecuredAuthenticatedDownloadRequest *asn1_secured_req = NULL;
  uint8_t *signed_req = NULL, *secured_req = NULL;

  /*
   * SignedAuthenticatedDownloadRequest 메시지 바이트열을 생성한다.
   */
  size_t signed_req_size;
  signed_req = dot2_ffasn1c_ConstructSignedAuthenticatedDownloadRequest(req_filename, cr_info, &_ret);
  if (!signed_req) {
    goto out;
  }
  signed_req_size = (size_t)_ret;

  /*
   * SignedAuthenticatedDownloadRequest 메시지 마이트열을 RA의 공개키로 암호화하여 securedAuthenticatedDownloadRequest 메시지에 수납한다.
   */
  asn1_secured_req = (dot2SecuredAuthenticatedDownloadRequest *)asn1_mallocz_value(asn1_type_dot2SecuredAuthenticatedDownloadRequest);
  if (!asn1_secured_req) {
    goto out;
  }
  _ret = dot2_ffasn1c_FillSecuredAuthenticatedDownloadRequest(signed_req, signed_req_size, cr_info, asn1_secured_req);
  if (_ret < 0) {
    goto out;
  }

  /*
   * securedAuthenticatedDownloadRequest 메시지를 인코딩한다.
   */
  size_t encoded_size;
  _ret = -kDot2Result_ASN1_EncodeCertDownloadRequest;
  secured_req = dot2_ffasn1c_EncodeSecuredScmsPDU(asn1_secured_req, &encoded_size);
  if (secured_req) {
    _ret = (int)encoded_size;
  }

out:
  *ret = _ret;
  if (asn1_secured_req) { asn1_free_value(asn1_type_dot2SecuredAuthenticatedDownloadRequest, asn1_secured_req); }
  if (signed_req) { free(signed_req); }
  return secured_req;
}


/**
 * @brief 인증서 다운로드응답문(SignedEncryptedCertificateResponse)을 파싱한다.
 * @param[in] cert_type 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] resp 인증서 다운로드응답문 바이트열
 * @param[in] resp_size 인증서 다운로드응답문 바이트열의 길이
 * @param[in] cert_enc_priv_key 인증서복호화용 개인키
 * @param[in] cert_enc_exp_key 인증서복호화용 개인키 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] i_preiod i-period 값 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] j_value j 값 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[out] resp_sign 인증서 다운로드응답문내 서명정보가 저장될 구조체 포인터(서명검증에 사용됨)
 * @param[out] resp_tbs_h 인증서 다운로드응답문내 ToBeSignedData 필드에 대한 해시값이 저장될 구조체 포인터(서명검증에 사용됨)
 * @param[out] recon_priv 인증서 다운로드응답문내 개인키 재구성값이 저장될 구조체 포인터
 * @param[out] cert 인증서 다운로드응답문내 인증서 바이트열이 저장될 구조체 포인터 (사용 후 free()해 주어야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseSignedEncryptedCertificateResponse(
  Dot2CMHType cert_type,
  const uint8_t *resp,
  Dot2SPDUSize resp_size,
  struct Dot2ECPrivateKey *cert_enc_priv_key,
  struct Dot2AESKey *cert_enc_exp_key,
  Dot2IPeriod i_period,
  Dot2CertJvalue j_value,
  struct Dot2Signature *resp_sign,
  struct Dot2SHA256 *resp_tbs_h,
  struct Dot2ECPrivateKey *recon_priv,
  struct Dot2Cert *cert)
{
  Log(kDot2LogLevel_Event, "Parse SignedEncryptedCertificateResponse\n");

  uint8_t *dec_cert_data = NULL, *encoded_cert = NULL;
  dot2SignedEncryptedCertificateResponse *asn1_secr = NULL;
  dot2ToBeSignedEncryptedCertificateResponse *asn1_tbsecr = NULL;
  dot2DecryptedCertificateData *asn1_dec_cert_data = NULL;
  dot2PlaintextCertificateResponse *asn1_plain_cr = NULL;

  /*
   * 인증서 다운로드응답문(SignedEncryptedCertificateResponse)을 디코딩한다.
   */
  asn1_secr = dot2_ffasn1c_DecodeSecuredScmsPDU(resp, resp_size);
  if (!asn1_secr) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_DecodeSecuredScmsPDU() failed\n");
    return -kDot2Result_ASN1_DecodeCertDownloadResponse;
  }

  /*
   * 인증서 다운로드응답문(SignedEncryptedCertificateResponse)의 형식이 유효한지 확인한다.
   */
  int ret;
  if ((asn1_secr->content.choice != dot2Ieee1609Dot2Content_signedData) ||
      (asn1_secr->content.u.signedData.signer.choice != dot2SignerIdentifier_digest) ||
      (asn1_secr->content.u.signedData.signer.u.digest.buf == NULL) ||
      (asn1_secr->content.u.signedData.signer.u.digest.len != 8) ||
      (asn1_secr->content.u.signedData.tbsData.payload.data_option == false) ||
      (asn1_secr->content.u.signedData.tbsData.payload.data == NULL) ||
      (asn1_secr->content.u.signedData.tbsData.payload.data->content.choice != dot2Ieee1609Dot2Content_unsecuredData) ||
      (asn1_secr->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.buf == NULL) ||
      (dot2_CheckSPDUSize(asn1_secr->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.len) == false)) {
    Err("Fail to parse SignedEncryptedCertificateResponse - invalid SignedEncryptedCertificateResponse contents\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }

  /*
   * 인증서 다운로드응답문(SignedEncryptedCertificateResponse) 내에서 서명정보를 추출한다.
   */
  ret = dot2_ffasn1c_ParseSignature((dot2Signature *)&(asn1_secr->content.u.signedData.signature), resp_sign);
  if (ret < 0) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_ParseSignature() failed\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }

  /*
   * 인증서 다운로드응답문(SignedEncryptedCertificateResponse) 내에서 ToBeSignedData 영역에 대한 인코딩 바이트열을 생성하고 해시값을 반환한다.
   *  - 서명검증을 위해 사용된다.
   */
  size_t tbs_size;
  uint8_t *tbs = dot2_ffasn1c_EncodeToBeSignedData(&(asn1_secr->content.u.signedData.tbsData), &tbs_size);
  if (tbs == NULL) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_EncodeToBeSignedData() failed\n");
    ret = -kDot2Result_ASN1_EncodeToBeSignedForSignature;
    goto out;
  }
  SHA256(tbs, tbs_size, resp_tbs_h->octs);
  free(tbs);

  /*
   * 암호화된 인증서응답문 내 TobeSignedEncryptedCertificateResponse 영역을 디코딩한다.
   */
  uint8_t *tbsecr = asn1_secr->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.buf;
  size_t tbsecr_size = asn1_secr->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.len;
  asn1_tbsecr = dot2_ffasn1c_DecodeToBeSignedEncryptedCertificateResponse(tbsecr, tbsecr_size);
  if (asn1_tbsecr == NULL) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_DecodeToBeSignedEncryptedCertificateResponse() failed\n");
    ret = -kDot2Result_ASN1_DecodeCertDownloadResponse;
    goto out;
  }

  /*
   * TobeSignedEncryptedCertificateResponse의 형식이 유효한지 확인한다.
   */
  if ((asn1_tbsecr->encrypted_cert.content.choice != dot2Ieee1609Dot2Content_encryptedData) ||
      (asn1_tbsecr->encrypted_cert.content.u.encryptedData.recipients.tab == NULL) ||
      (asn1_tbsecr->encrypted_cert.content.u.encryptedData.recipients.count == 0) ||
      (asn1_tbsecr->encrypted_cert.content.u.encryptedData.ciphertext.u.aes128ccm.nonce.buf == NULL) ||
      (asn1_tbsecr->encrypted_cert.content.u.encryptedData.ciphertext.u.aes128ccm.nonce.len != DOT2_AES_128_NONCE_LEN) ||
      (asn1_tbsecr->encrypted_cert.content.u.encryptedData.ciphertext.u.aes128ccm.ccmCiphertext.buf == NULL)) {
    Err("Fail to parse SignedEncryptedCertificateResponse - Invalid TobeSignedEncryptedCertificateResponse contents\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }

  dot2RecipientInfo *asn1_recipient = asn1_tbsecr->encrypted_cert.content.u.encryptedData.recipients.tab;

  /*
   * TobeSignedEncryptedCertificateResponse 내 수신자정보(RecipientInfo)의 형식이 유효한지 확인한다.
   */
  if ((asn1_recipient->choice != dot2RecipientInfo_rekRecipInfo) ||
      (asn1_recipient->u.rekRecipInfo.encKey.choice != dot2EncryptedDataEncryptionKey_eciesNistP256) ||
      (asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.c.buf == NULL) ||
      (asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.c.len != DOT2_AES_128_LEN) ||
      (asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.t.buf == NULL) ||
      (asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.t.len != DOT2_AUTH_TAG_LEN)) {
    Err("Fail to parse SignedEncryptedCertificateResponse - Invalid RecipientInfo contents\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }

  /*
   * TobeSignedEncryptedCertificateResponse 내 수신자정보(RecipientInfo)에서 C,T,V를 추출한다.
   *  - C: AES 공개키 바이트열
   *  - T: Authentication tag 바이트열
   *  - V: 임시 공개키
   */
  struct Dot2AESKey C;
  struct Dot2AESAuthTag T;
  memcpy(C.octs, asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.c.buf, sizeof(C.octs));
  memcpy(T.octs, asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.t.buf, sizeof(T.octs));
  dot2EccP256CurvePoint *asn1_V = &(asn1_recipient->u.rekRecipInfo.encKey.u.eciesNistP256.v);
  struct Dot2ECPublicKey V;
  ret = dot2_ffasn1c_ParseEccP256CurvePoint((const dot2EccP256CurvePoint *)asn1_V, &V);
  if (ret < 0) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_ParseEccP256CurvePoint() failed\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }


  /*
   * 익명/식별인증서인 경우 인증서복호화용 Cocoon 키를 생성한다.
   * 응용인증서인 경우에는 전달된 개인키를 그대로 사용한다.
   */
  struct Dot2ECPrivateKey *_cert_enc_priv_key;
  struct Dot2ECKeyPairOcts cocoon_key;
  if ((cert_type == kDot2CMHType_Pseudonym) ||
      (cert_type == kDot2CMHType_Identification)) {
    ret = dot2_ossl_MakeEncryptionCocoonKeyPair(i_period, j_value, cert_enc_exp_key, cert_enc_priv_key, &cocoon_key);
    if (ret < 0) {
      Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ossl_MakeEncryptionCocoonKeyPair() failed\n");
      goto out;
    }
    _cert_enc_priv_key = &(cocoon_key.priv_key);
  } else {
    _cert_enc_priv_key = cert_enc_priv_key;
  }

  /*
   * TobeSignedEncryptedCertificateResponse 내 암호문(SymmetricCiphertext)을 복호화한다.
   *  => 복호화결과: DecryptedCertificateData(=Ieee1609Dot2Data)
   */
  dot2SymmetricCiphertext *asn1_ciphertext = &(asn1_tbsecr->encrypted_cert.content.u.encryptedData.ciphertext);
  struct Dot2AESNonce nonce;
  memcpy(nonce.octs, asn1_ciphertext->u.aes128ccm.nonce.buf, sizeof(nonce.octs));
  uint8_t *ctext = asn1_ciphertext->u.aes128ccm.ccmCiphertext.buf;
  size_t ctext_len = asn1_ciphertext->u.aes128ccm.ccmCiphertext.len;
  dec_cert_data = dot2_DecryptData_1(ctext, ctext_len, NULL, 0, _cert_enc_priv_key, &V, &C, &T, &nonce, &ret);
  if (dec_cert_data == NULL) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_DecryptData_1() failed\n");
    ret = -kDot2Result_LCM_DecryptCertDownloadResponse;
    goto out;
  }
  size_t dec_cert_data_size = (size_t)ret;

  /*
   * 복호화된 결과인 DecryptedCertificateData를 디코딩한다.
   */
  asn1_dec_cert_data = dot2_ffasn1c_DecodeSecuredScmsPDU(dec_cert_data, dec_cert_data_size);
  if (asn1_dec_cert_data == NULL) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_DecodeSecuredScmsPDU(DecryptedCertificateData) failed\n");
    ret = -kDot2Result_ASN1_DecodeCertDownloadResponse;
    goto out;
  }

  /*
   * DecryptedCertificateData의 형식이 유효한지 확인한다.
   */
  if ((asn1_dec_cert_data->content.choice != dot2Ieee1609Dot2Content_unsecuredData) ||
      (asn1_dec_cert_data->content.u.unsecuredData.buf == NULL) ||
      (dot2_CheckSPDUSize(asn1_dec_cert_data->content.u.unsecuredData.len) == false)) {
    Err("Fail to parse SignedEncryptedCertificateResponse - Invalid DecryptedCertificateData contents\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }

  /*
   * DecryptedCertificateData 내에 unsecuredData 필드에 포함된 PlaintextCertificateResponse를 디코딩한다.
   */
  uint8_t *plain_cr = asn1_dec_cert_data->content.u.unsecuredData.buf;
  size_t plain_cr_size = asn1_dec_cert_data->content.u.unsecuredData.len;
  asn1_plain_cr = dot2_ffasn1c_DecodePlaintextCertificateResponse(plain_cr, plain_cr_size);
  if (asn1_plain_cr == NULL) {
    Err("Fail to parse SignedEncryptedCertificateResponse - dot2_ffasn1c_DecodePlaintextCertificateResponse() failed\n");
    ret = -kDot2Result_ASN1_DecodeCertDownloadResponse;
    goto out;
  }

  /*
   * PlaintextCertificateResponse의 형식이 유효한지 확인한다.
   */
  ret = -1;
  if (cert_type == kDot2CMHType_Application) {
    ret = 0;
    if ((asn1_plain_cr->choice != dot2PlaintextCertificateResponse_implicit) ||
        (asn1_plain_cr->u.implicit.priv_key_reconstruction_s.buf == NULL) ||
        (asn1_plain_cr->u.implicit.priv_key_reconstruction_s.len != DOT2_EC_256_KEY_LEN) ||
        (asn1_plain_cr->u.implicit.certificate.toBeSigned.verifyKeyIndicator.choice !=
         dot2VerificationKeyIndicator_reconstructionValue)) {
      ret = -1;
    }
  } else if ((cert_type == kDot2CMHType_Pseudonym) ||
             (cert_type == kDot2CMHType_Identification)) {
    ret = 0;
    if ((asn1_plain_cr->choice != dot2PlaintextCertificateResponse_implicit_butterfly) ||
        (asn1_plain_cr->u.implicit_butterfly.priv_key_reconstruction_s.buf == NULL) ||
        (asn1_plain_cr->u.implicit_butterfly.priv_key_reconstruction_s.len != DOT2_EC_256_KEY_LEN) ||
        (asn1_plain_cr->u.implicit_butterfly.certificate.toBeSigned.verifyKeyIndicator.choice !=
         dot2VerificationKeyIndicator_reconstructionValue)) {
      ret = -1;
    }
  }
  if (ret < 0) {
    Err("Fail to parse SignedEncryptedCertificateResponse - Invalid PlaintextCertificateResponse contents\n");
    ret = -kDot2Result_LCM_InvalidCertDownloadResponse;
    goto out;
  }

  /*
   * PlaintextCertificateResponse 내에서 개인키재구성값, 인증서바이트열을 추출한다.
   * 인증서바이트열은 직접 인코딩해야 한다.
   */
  dot2Certificate *asn1_cert = &(asn1_plain_cr->u.implicit.certificate);
  dot2EccP256PrivateKeyReconstruction *asn1_recon_priv = &(asn1_plain_cr->u.implicit.priv_key_reconstruction_s);
  memcpy(recon_priv->octs, asn1_recon_priv->buf, DOT2_EC_256_KEY_LEN);
  encoded_cert = dot2_ffasn1c_EncodeCertificate((dot2Certificate *)asn1_cert, &(cert->size));
  if (encoded_cert == NULL) {
    ret = -kDot2Result_ASN1_EncodeCertificate;
    goto out;
  }

  if (cert->size > sizeof(cert->octs)) {
    Err("Fail to Parse SignedEncryptedCertificateResponse - too long cert size: %zu\n", cert->size);
    goto out;
  }

  Log(kDot2LogLevel_Event, "Success to parse SignedEncryptedCertificateResponse\n");
  memcpy(cert->octs, encoded_cert, cert->size);
  ret = kDot2Result_Success;

out:
  if (dec_cert_data) { free(dec_cert_data); }
  if (encoded_cert) { free(encoded_cert); }
  if (asn1_secr) { asn1_free_value(asn1_type_dot2SignedEncryptedCertificateResponse, asn1_secr); }
  if (asn1_tbsecr) { asn1_free_value(asn1_type_dot2ToBeSignedEncryptedCertificateResponse, asn1_tbsecr); }
  if (asn1_dec_cert_data) { asn1_free_value(asn1_type_dot2DecryptedCertificateData, asn1_dec_cert_data); }
  if (asn1_plain_cr) { asn1_free_value(asn1_type_dot2PlaintextCertificateResponse, asn1_plain_cr); }
  return ret;
}


/**
 * @brief 인증서 다운로드일정정보 응답문을 파싱한다.
 * @param[in] resp 인증서 다운로드일정정보 응답문 바이트열
 * @param[in] resp_size 인증서 다운로드일정정보 응답문 바이트열의 길이
 * @param[out] cert_dl_time 다운로드 가능시간이 저장될 변수 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseCertDownloadInfoResponse(const uint8_t *resp, size_t resp_size, Dot2Time32 *cert_dl_time)
{
  Log(kDot2LogLevel_Event, "Parse cert download info response\n");

  /*
   * 응답문을 디코딩한다.
   */
  dot2Time32 *asn1_resp = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn1_resp, asn1_type_dot2Time32, resp, resp_size, &err1);
  if ((decoded_size < 0) ||
      (asn1_resp == NULL)) {
    return -kDot2Result_ASN1_DeocdeCertDownloadInfoResponse;
  }

  /*
   * 정보를 파싱/반환한다.
   */
  *cert_dl_time = *asn1_resp;
  asn1_free_value(asn1_type_dot2Time32, asn1_resp);
  return kDot2Result_Success;
}
