/** 
  * @file 
  * @brief 인증서 공급요청 관련 구현
  * @date 2022-08-13 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-internal-inline.h"
#include "asn1/ffasn1c/dot2-ffasn1c.h"
#include "asn1/ffasn1c/dot2-ffasn1c-inline.h"
#include "lcm/dot2-lcm.h"


/**
 * @brief 인증서 발급요청문 내 ScopedAppCertProvisioningRequest/ScopedPseudonymCertProvisioningRequest/
 *        ScopedIdCertProvisioningRequest 필드를 채운다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] current_time 현재시각
 * @param[in] start_time 인증서 유효기간 시작시점
 * @param[in] verify_pub_key 서명용 임시공개키(cert_type=App) 또는 caterpillar 공개키(cert_type=Pseudony/Id)
 * @param[in] cert_enc_pub_key 발급될 인증서 암호화용 공개키
 * @param[in] verify_exp_key 서명용 개인키 확장을 위한 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cert_enc_exp_key 인증서복호화용 개인키 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[out] asn1_cr 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * ScopedAppCertProvisioningRequest/ScopedPseudonymCertProvisioningRequest/ScopedIdCertProvisioningRequest
 * 3가지 정보 형식은 모두 ScmsPDU 형식과 동일하다.
 * 3종류(응용/익명/식별) 인증서에 대해 공통으로 사용되는 함수이므로 ScmsPDU로써 처리한다.
 */
static int dot2_ffasn1c_FillScopedCertProvisioningRequest(
  Dot2CMHType cert_type,
  Dot2Time32 current_time,
  Dot2Time32 start_time,
  const struct Dot2ECPublicKey *verify_pub_key,
  const struct Dot2ECPublicKey *cert_enc_pub_key,
  const struct Dot2AESKey *verify_exp_key,
  const struct Dot2AESKey *cert_enc_exp_key,
  dot2ScmsPDU *asn1_cr)
{
  Log(kDot2LogLevel_Event, "Fill ScopedCertProvisioningRequest\n");

  int ret;
  asn1_cr->version = KDot2ScmsPDUVersion_SCMS;
  asn1_cr->content.choice = dot2ScmsPDU_1_ee_ra;
  if (cert_type == kDot2CMHType_Application) {
    asn1_cr->content.u.ee_ra.choice = dot2EndEntityRaInterfacePDU_eeRaAppCertProvisioningRequest;
    dot2EeRaAppCertProvisioningRequest *asn1_req = &(asn1_cr->content.u.ee_ra.u.eeRaAppCertProvisioningRequest);
    return dot2_ffasn1c_FillEeRaAppCertProvisioningRequest(current_time,
                                                           start_time,
                                                           verify_pub_key,
                                                           cert_enc_pub_key,
                                                           asn1_req);
  } else if (cert_type == kDot2CMHType_Pseudonym) {
    asn1_cr->content.u.ee_ra.choice = dot2EndEntityRaInterfacePDU_eeRaPseudonymCertProvisioningRequest;
    dot2EeRaPseudonymCertProvisioningRequest *asn1_req = &(asn1_cr->content.u.ee_ra.u.eeRaPseudonymCertProvisioningRequest);
    return dot2_ffasn1c_FillEeRaPseudonymCertProvisioningRequest(current_time,
                                                                 start_time,
                                                                 verify_pub_key,
                                                                 cert_enc_pub_key,
                                                                 verify_exp_key,
                                                                 cert_enc_exp_key,
                                                                 asn1_req);
  } else {
    asn1_cr->content.u.ee_ra.choice = dot2EndEntityRaInterfacePDU_eeRaIdCertProvisioningRequest;
    dot2EeRaIdCertProvisioningRequest *asn1_req = &(asn1_cr->content.u.ee_ra.u.eeRaIdCertProvisioningRequest);
    ret = dot2_ffasn1c_FillEeRaIdCertProvisioningRequest(current_time,
                                                         start_time,
                                                         verify_pub_key,
                                                         cert_enc_pub_key,
                                                         verify_exp_key,
                                                         cert_enc_exp_key,
                                                         asn1_req);
  }
  return ret;
}


/**
 * @brief 인증서 발급요청문 내 SignedCertificateRequest 필드를 Opaque 형식으로 채운다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] current_time 현재시각
 * @param[in] start_time 인증서 유효기간 시작시점
 * @param[in] verify_pub_key 서명용 임시공개키(cert_type=App) 또는 caterpillar 공개키(cert_type=Pseudony/Id)
 * @param[in] cert_enc_pub_key 발급될 인증서 암호화용 공개키
 * @param[in] verify_exp_key 서명용 개인키 확장을 위한 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cert_enc_exp_key 인증서복호화용 개인키 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] asn1_cr_opaque 정보를 채울 asn.1 정보 구조체
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static int dot2_ffasn1c_FillSignedCertificateRequest(
  Dot2CMHType cert_type,
  Dot2Time32 current_time,
  Dot2Time32 start_time,
  const struct Dot2ECPublicKey *verify_pub_key,
  const struct Dot2ECPublicKey *cert_enc_pub_key,
  const struct Dot2AESKey *verify_exp_key,
  const struct Dot2AESKey *cert_enc_exp_key,
  struct Dot2CertRequestInfo *cr_info,
  dot2Opaque *asn1_cr_opaque)
{
  Log(kDot2LogLevel_Event, "Fill SignedCertificateRequest\n");

  int ret = -kDot2Result_NoMemory;
  uint8_t *encoded = NULL;
  dot2SignedCertificateRequest *asn1_cr;
  asn1_cr = (dot2SignedCertificateRequest *)asn1_mallocz_value(asn1_type_dot2SignedCertificateRequest);
  if (asn1_cr) {

    // signedCertificateRequest.hashId 내용을 채운다.
    asn1_cr->hashId = dot2HashAlgorithm_sha256;

    // signedCertificateRequest.Scoped***CertProvisioningRequest 내용을 채운다.
    ret = dot2_ffasn1c_FillScopedCertProvisioningRequest(cert_type,
                                                         current_time,
                                                         start_time,
                                                         verify_pub_key,
                                                         cert_enc_pub_key,
                                                         verify_exp_key,
                                                         cert_enc_exp_key,
                                                         &(asn1_cr->tbsRequest));
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
      asn1_cr_opaque->len = (size_t)encoded_size;
      asn1_cr_opaque->buf = encoded;
      ret = kDot2Result_Success;
    }
  }

out:
  if (asn1_cr) { asn1_free_value(asn1_type_dot2SignedCertificateRequest, asn1_cr); }
  return ret;
}

/**
 * @brief SignedAppCertProvisioningRequest/SecuredPseudonymCertProvisioningRequest/SecuredIdCertProvisioningRequest
 *        메시지 바이트열을 생성한다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] current_time 현재시각
 * @param[in] start_time 인증서 유효기간 시작시점
 * @param[in] verify_pub_key 서명용 임시공개키(cert_type=App) 또는 caterpillar 공개키(cert_type=Pseudony/Id)
 * @param[in] cert_enc_pub_key 발급될 인증서 암호화용 공개키
 * @param[in] verify_exp_key 서명용 개인키 확장을 위한 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cert_enc_exp_key 인증서복호화용 개인키 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] ret 인코딩 결과가 저장될 변수 포인터. 성공 시 인코딩된 메시지의 길이, 실패 시 음수(-Dot2ResultCode)가 저장된다.
 * @return OER 인코딩된 메시지 바이트열. 동적할당된 정보이므로 사용 후 free()해 주어야 한다.
 *
 * SignedAppCertProvisioningRequest/SignedPseudonymCertProvisioningRequest/SignedIdCertProvisioningRequest
 * 3가지 정보 형식은 모두 dot2SecuredScmsPDU 형식과 동일하다.
 * 3종류(응용/익명/식별) 인증서에 대해 공통으로 사용되는 함수이므로 SecuredScmsPDU로써 처리한다.
 */
static uint8_t * dot2_ffasn1c_ConstructSignedCertProvisioningRequest(
  Dot2CMHType cert_type,
  Dot2Time32 current_time,
  Dot2Time32 start_time,
  const struct Dot2ECPublicKey *verify_pub_key,
  const struct Dot2ECPublicKey *cert_enc_pub_key,
  const struct Dot2AESKey *verify_exp_key,
  const struct Dot2AESKey *cert_enc_exp_key,
  struct Dot2CertRequestInfo *cr_info,
  int *ret)
{
  Log(kDot2LogLevel_Event, "Construct SignedCertProvisioningRequest\n");

  *ret = -kDot2Result_NoMemory;
  uint8_t *signed_req = NULL;
  dot2SecuredScmsPDU *asn1_signed_req = asn1_mallocz_value(asn1_type_dot2SecuredScmsPDU);
  if (asn1_signed_req) {

    asn1_signed_req->protocolVersion = DOT2_PROTOCOL_VERSION;
    asn1_signed_req->content.choice = dot2Ieee1609Dot2Content_signedCertificateRequest;

    /*
     * Signed***CertProvisioningRequest 내 signedCertificateRequest 필드를 채운다.
     */
    dot2Opaque *asn1_cr = &(asn1_signed_req->content.u.signedCertificateRequest);
    *ret = dot2_ffasn1c_FillSignedCertificateRequest(cert_type,
                                                     current_time,
                                                     start_time,
                                                     verify_pub_key,
                                                     cert_enc_pub_key,
                                                     verify_exp_key,
                                                     cert_enc_exp_key,
                                                     cr_info,
                                                     asn1_cr);
    if (*ret < 0) {
      goto out;
    }

    /*
     * Signed***CertProvisioningRequest 메시지를 OER 인코딩한다.
     */
    size_t encoded_size;
    *ret = -kDot2Result_ASN1_EncodeCertProvisioningRequest;
    signed_req = dot2_ffasn1c_EncodeSecuredScmsPDU(asn1_signed_req, &encoded_size);
    if (signed_req) {
      *ret = (int)encoded_size;
    }
  }

out:
  if (asn1_signed_req) { asn1_free_value(asn1_type_dot2SecuredScmsPDU, asn1_signed_req); }
  return signed_req;
}


/**
 * @brief 인증서 발급요청문 내 SecuredAppCertProvisioningRequest/SecuredPseudonymCertProvisioningRequest/
 *        SecuredIdCertProvisioningRequest 필드를 채운다.
 * @param[in] signed_req Signed***CertProvisioningRequest 메시지 바이트열 (암호화 대상)
 * @param[in] signed_req_size signed_acpr의 길이
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] asn1_secured_req 정보를 채울 asn.1 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * SecuredAppCertProvisioningRequest/SecuredPseudonymCertProvisioningRequest/SecuredIdCertProvisioningRequest
 * 3가지 정보 형식은 모두 dot2SecuredScmsPDU 형식과 동일하다.
 * 3종류(응용/익명/식별) 인증서에 대해 공통으로 사용되는 함수이므로 SecuredScmsPDU로써 처리한다.
 */
static int dot2_ffasn1c_FillSecuredCertProvisioningRequest(
  uint8_t *signed_req,
  size_t signed_req_size,
  struct Dot2CertRequestInfo *cr_info,
  dot2SecuredScmsPDU *asn1_secured_req)
{
  Log(kDot2LogLevel_Event, "Fill Secured***CertProvisioningRequest\n");
  asn1_secured_req->protocolVersion = DOT2_PROTOCOL_VERSION;
  asn1_secured_req->content.choice = dot2Ieee1609Dot2Content_encryptedData;
  return dot2_ffasn1c_FillEncryptedData(signed_req,
                                        signed_req_size,
                                        &(cr_info->ra.cert_h),
                                        &(cr_info->ra.enc_pub_key),
                                        &(asn1_secured_req->content.u.encryptedData));
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 인증서발급요청문을 생성한다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] current_time 현재시각
 * @param[in] start_time 인증서 유효기간 시작시점
 * @param[in] verify_pub_key 서명용 임시공개키(cert_type=App) 또는 caterpillar 공개키(cert_type=Pseudony/Id)
 * @param[in] cert_enc_pub_key 발급될 인증서 암호화용 공개키
 * @param[in] verify_exp_key 서명용 개인키 확장을 위한 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cert_enc_exp_key 인증서복호화용 개인키 확장함수 키 (cert_type=Pseudonym/Id인 경우에만 사용된다)
 * @param[in] cr_info 인증서요청 관련 정보
 * @param[out] ret 인코딩 결과가 저장될 변수 포인터. 성공 시 인코딩된 발급요청문의 길이, 실패 시 음수(-Dot2ResultCode)가 저장된다.
 * @return OER 인코딩된 인증서 발급요청문 바이트열. 동적할당된 정보이므로 사용 후 free()해 주어야 한다.
 *
 * SecuredAppCertProvisioningRequest/SecuredPseudonymCertProvisioningRequest/SecuredIdCertProvisioningRequest
 * 3가지 정보 형식은 모두 dot2SecuredScmsPDU 형식과 동일하다.
 * 3종류(응용/익명/식별) 인증서에 대해 공통으로 사용되는 함수이므로 SecuredScmsPDU로써 처리한다.
 */
uint8_t INTERNAL * dot2_ffasn1c_ConstructSecuredCertProvisioningRequest(
  Dot2CMHType cert_type,
  Dot2Time32 current_time,
  Dot2Time32 start_time,
  const struct Dot2ECPublicKey *verify_pub_key,
  const struct Dot2ECPublicKey *cert_enc_pub_key,
  const struct Dot2AESKey *verify_exp_key,
  const struct Dot2AESKey *cert_enc_exp_key,
  struct Dot2CertRequestInfo *cr_info,
  int *ret)
{
  int _ret;
  Log(kDot2LogLevel_Event, "Construct cert provisioning request\n");

  dot2SecuredScmsPDU *asn1_secured_req = NULL;
  uint8_t *signed_req = NULL, *secured_req = NULL;

  /*
   * Signed***CertProvisioningRequest 메시지 바이트열을 생성한다.
   */
  size_t signed_req_size;
  signed_req = dot2_ffasn1c_ConstructSignedCertProvisioningRequest(cert_type,
                                                                   current_time,
                                                                   start_time,
                                                                   verify_pub_key,
                                                                   cert_enc_pub_key,
                                                                   verify_exp_key,
                                                                   cert_enc_exp_key,
                                                                   cr_info,
                                                                   &_ret);
  if (signed_req == NULL) {
    goto out;
  }
  signed_req_size = (size_t)_ret;

  /*
   * Signed***CertProvisioningRequest 메시지 마이트열을 RA의 공개키로 암호화하여 Signed***CertProvisioningRequest 메시지에 수납한다.
   */
  asn1_secured_req = asn1_mallocz_value(asn1_type_dot2SecuredScmsPDU);
  if (asn1_secured_req == NULL) {
    goto out;
  }
  _ret = dot2_ffasn1c_FillSecuredCertProvisioningRequest(signed_req, signed_req_size, cr_info, asn1_secured_req);
  if (_ret < 0) {
    goto out;
  }

  /*
   * Secured***CertProvisioningRequest 메시지를 인코딩한다.
   */
  size_t encoded_size;
  _ret = -kDot2Result_ASN1_EncodeCertProvisioningRequest;
  secured_req = dot2_ffasn1c_EncodeSecuredScmsPDU(asn1_secured_req, &encoded_size);
  if (!secured_req) {
    Err("Fail to construct cert provisioning request - dot2_ffasn1c_EncodeSecuredScmsPDU() failed\n");
    goto out;
  }

  Log(kDot2LogLevel_Event, "Success to construct cert provisioning request\n");
  _ret = (int)encoded_size;

out:
  *ret = _ret;
  if (asn1_secured_req) { asn1_free_value(asn1_type_dot2SecuredScmsPDU, asn1_secured_req); }
  if (signed_req) { free(signed_req); }
  return secured_req;
}



/**
 * @brief 인증서 발급응답문 내 ScopedAppCertProvisioningAck/ScopedPseudonymCertProvisioningAck/ScopedIdCertProvisioningAck 메시지를 파싱한다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] scoped_ack 파싱할 인증서 발급응답문 내 Scoped***CertProvisioningAck 바이트열
 * @param[in] scoped_ack_size scoped_ack의 길이
 * @param[out] req_h8 인증서 발급응답문 내에 포함된 requestHash값이 반환될 버퍼(8바이트 길이를 가진다)
 * @param[out] cert_dl_time 인증서 발급응답문 내에 포함된 다운로드 가능시간이 저장될 변수 포인터
 * @param[out] cert_dl_url 인증서 발급응답문 내에 포함된 다운로드 URL이 저장될 변수 포인터 (사용 후 free() 되어야 한다)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * ScopedAppCertProvisioningAck/ScopedPseudonymCertProvisioningAck/ScopedIdCertProvisioningAck
 * 3가지 정보 형식은 모두 ScmsPDU 형식과 동일하다.
 * 3종류(응용/익명/식별) 인증서에 대해 공통으로 사용되는 함수이므로 ScmsPDU로써 처리한다.
 */
static int dot2_ffasn1c_ParseScopedCertProvisioningAck(
  Dot2CMHType cert_type,
  const uint8_t *scoped_ack,
  Dot2SPDUSize scoped_ack_size,
  uint8_t *req_h8,
  Dot2Time32 *cert_dl_time,
  char **cert_dl_url)
{
  int ret;
  Log(kDot2LogLevel_Event, "Parse Scoped***CertProvisioningAck\n");

  /*
   * ScopedAppCertProvisioningAck/ScopedPseudonymCertProvisioningAck/ScopedIdCertProvisioningAck 메시지를 디코딩한다.
   */
  dot2ScmsPDU *asn1_scoped_ack = dot2_ffasn1c_DecodeScmsPDU(scoped_ack, scoped_ack_size);
  if (!asn1_scoped_ack) {
    Err("Fail to parse Scoped***CertProvisioningAck - dot2_ffasn1c_DecodeScmsPDU(pcp_resp) failed\n");
    return -kDot2Result_ASN1_DecodeCertProvisioningAck;
  }

  /*
   * ScopedAppCertProvisioningAck/ScopedPseudonymCertProvisioningAck/ScopedIdCertProvisioningAck의 형식이 유효한지 확인한다.
   */
  ret = -1;
  if (asn1_scoped_ack->content.choice == dot2ScmsPDU_1_ee_ra) {
    ret = 0;
    dot2EndEntityRaInterfacePDU *asn1_pdu = &(asn1_scoped_ack->content.u.ee_ra);
    if (cert_type == kDot2CMHType_Application) {
      if ((asn1_pdu->choice != dot2EndEntityRaInterfacePDU_raEeAppCertProvisioningAck) ||
          (asn1_pdu->u.raEeAppCertProvisioningAck.requestHash.buf == NULL) ||
          (asn1_pdu->u.raEeAppCertProvisioningAck.requestHash.len != 8) ||
          (asn1_pdu->u.raEeAppCertProvisioningAck.reply.choice != dot2RaEePseudonymCertProvisioningAck_1_ack) ||
          (asn1_pdu->u.raEeAppCertProvisioningAck.reply.u.ack.certDLURL.buf == NULL) ||
          (asn1_pdu->u.raEeAppCertProvisioningAck.reply.u.ack.certDLURL.len > DOT2_HTTP_URL_HOSTNAME_STR_MAX_LEN)) {
        ret = -1;
      }
    } else if (cert_type == kDot2CMHType_Pseudonym) {
      if ((asn1_pdu->choice != dot2EndEntityRaInterfacePDU_raEePseudonymCertProvisioningAck) ||
          (asn1_pdu->u.raEePseudonymCertProvisioningAck.requestHash.buf == NULL) ||
          (asn1_pdu->u.raEePseudonymCertProvisioningAck.requestHash.len != 8) ||
          (asn1_pdu->u.raEePseudonymCertProvisioningAck.reply.choice != dot2RaEePseudonymCertProvisioningAck_1_ack) ||
          (asn1_pdu->u.raEePseudonymCertProvisioningAck.reply.u.ack.certDLURL.buf == NULL) ||
          (asn1_pdu->u.raEePseudonymCertProvisioningAck.reply.u.ack.certDLURL.len > DOT2_HTTP_URL_HOSTNAME_STR_MAX_LEN)) {
        ret = -1;
      }
    } else { //(cert_type == kDot2CMHType_Identification)
      if ((asn1_pdu->choice != dot2EndEntityRaInterfacePDU_raEeIdCertProvisioningAck) ||
          (asn1_pdu->u.raEeIdCertProvisioningAck.requestHash.buf == NULL) ||
          (asn1_pdu->u.raEeIdCertProvisioningAck.requestHash.len != 8) ||
          (asn1_pdu->u.raEeIdCertProvisioningAck.reply.choice != dot2RaEePseudonymCertProvisioningAck_1_ack) ||
          (asn1_pdu->u.raEeIdCertProvisioningAck.reply.u.ack.certDLURL.buf == NULL) ||
          (asn1_pdu->u.raEeIdCertProvisioningAck.reply.u.ack.certDLURL.len > DOT2_HTTP_URL_HOSTNAME_STR_MAX_LEN)) {
        ret = -1;
      }
    }
  }
  if (ret < 0) {
    Err("Fail to parse Scoped***CertProvisioningAck - invalid Scoped***CertProvisioningAck contents\n");
    ret = -kDot2Result_LCM_InvalidCertProvisioningAck;
    goto out;
  }

  /*
   * 응답문내에 포함된 requestHash값, 다운로드가능시간, URL 정보를 반환한다.
   * App/Pseudonym/Id 인증서 모두 dot2RaEePseudonymCertProvisioningAck 형식을 가진다.
   */
  dot2RaEePseudonymCertProvisioningAck *asn1_ack = &(asn1_scoped_ack->content.u.ee_ra.u.raEePseudonymCertProvisioningAck);
  memcpy(req_h8, asn1_ack->requestHash.buf, 8);
  *cert_dl_time = asn1_ack->reply.u.ack.certDLTime;
  *cert_dl_url = calloc(1, asn1_ack->reply.u.ack.certDLURL.len);
  if (*cert_dl_url == NULL) {
    ret = -kDot2Result_NoMemory;
    goto out;
  }
  memcpy(*cert_dl_url, asn1_ack->reply.u.ack.certDLURL.buf, asn1_ack->reply.u.ack.certDLURL.len);
  ret = kDot2Result_Success;
  Log(kDot2LogLevel_Event, "Success to parse Scoped***CertProvisioningAck\n");

out:
  asn1_free_value(asn1_type_dot2ScmsPDU, asn1_scoped_ack);
  return ret;
}


/**
 * @brief 인증서 발급응답문(SignedAppCertProvisioningAck/SignedPseudonymCertProvisioningAck/SignedIdCertProvisioningAck)을 파싱한다.
 * @param[in] cert_type 요청 인증서 유형 (App/Pseudonym/Id 가능)
 * @param[in] ack 파싱할 인증서 발급응답문 바이트열
 * @param[in] ack_size 인증서 발급응답문 바이트열의 길이
 * @param[out] req_h8 인증서 발급응답문 내에 포함된 requestHash값이 반환될 버퍼(8바이트 길이를 가진다)
 * @param[out] cert_dl_time 인증서 발급응답문 내에 포함된 다운로드 가능시간이 저장될 변수 포인터
 * @param[out] cert_dl_url 인증서 발급응답문 내에 포함된 다운로드 URL이 저장될 변수 포인터 (사용 후 free() 되어야 한다)
 * @param[out] tbs 파싱된 ToBeSignedData 바이트열이 저장될 버퍼 포인터
 * @param[out] tbs_size 파싱된 ToBeSignedData 바이트열의 길이가 저장될 변수 포인터
 * @param[out] sign 파싱된 서명정보가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 *
 * SignedAppCertProvisioningAck/SignedPseudonymCertProvisioningAck/SignedIdCertProvisioningAck
 * 3가지 정보 형식은 모두 SecuredScmsPDU 형식과 동일하다.
 * 3종류(응용/익명/식별) 인증서에 대해 공통으로 사용되는 함수이므로 SecuredScmsPDU로써 처리한다.
 */
int INTERNAL dot2_ffasn1c_ParseSignedCertProvisioningAck(
  Dot2CMHType cert_type,
  const uint8_t *ack,
  Dot2SPDUSize ack_size,
  uint8_t *req_h8,
  Dot2Time32 *cert_dl_time,
  char **cert_dl_url,
  uint8_t **tbs,
  Dot2SPDUSize *tbs_size,
  struct Dot2Signature *sign)
{
  int ret;
  Log(kDot2LogLevel_Event, "Parse Signed***CertProvisioningAck\n");

  /*
   * 인증서발급응답문(Signed***CertProvisioningAck)을 디코딩한다.
   */
  dot2SecuredScmsPDU *asn1_signed_ack = dot2_ffasn1c_DecodeSecuredScmsPDU(ack, ack_size);
  if (!asn1_signed_ack) {
    Err("Fail to parse Signed***CertProvisioningAck - dot2_ffasn1c_DecodeSecuredScmsPDU(ack) failed\n");
    return -kDot2Result_ASN1_DecodeCertProvisioningAck;
  }

  /*
   * 인증서발급응답문(Signed***CertProvisioningAck)의 형식이 유효한지 확인한다.
   */
  if ((asn1_signed_ack->content.choice != dot2Ieee1609Dot2Content_signedData) ||
      (asn1_signed_ack->content.u.signedData.tbsData.payload.data_option == false) ||
      (asn1_signed_ack->content.u.signedData.tbsData.payload.data == NULL) ||
      (asn1_signed_ack->content.u.signedData.tbsData.payload.data->content.choice != dot2Ieee1609Dot2Content_unsecuredData) ||
      (asn1_signed_ack->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.buf == NULL) ||
      (asn1_signed_ack->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.len == 0)) {
    Err("Fail to parse Signed***CertProvisioningAck - invalid message contents\n");
    ret = -kDot2Result_LCM_InvalidCertProvisioningAck;
    goto out;
  }

  /*
   * 인증서발급응답문 내 Scoped***CertProvisioningAck 메시지를 파싱한다.
   */

  uint8_t *scoped_ack = asn1_signed_ack->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.buf;
  size_t scoped_ack_size = asn1_signed_ack->content.u.signedData.tbsData.payload.data->content.u.unsecuredData.len;
  ret = dot2_ffasn1c_ParseScopedCertProvisioningAck(cert_type,
                                                    scoped_ack,
                                                    scoped_ack_size,
                                                    req_h8,
                                                    cert_dl_time,
                                                    cert_dl_url);
  if (ret < 0) {
    goto out;
  }

  /*
   * 서명검증을 위해 인증서발급응답문 내 서명정보를 파싱한다.
   */
  ret = dot2_ffasn1c_ParseSignature((const dot2Signature *)&(asn1_signed_ack->content.u.signedData.signature), sign);
  if (ret < 0) {
    goto out;
  }

  /*
   * 서명검증을 위해 TBS를 생성하여 반환한다.
   */
  *tbs = dot2_ffasn1c_EncodeToBeSignedData(&(asn1_signed_ack->content.u.signedData.tbsData), tbs_size);
  if (*tbs == NULL) {
    Err("Fail to parse Signed***CertProvisioningAck - dot2_ffasn1c_EncodeToBeSignedData() failed\n");
    ret = -kDot2Result_ASN1_EncodeToBeSignedForSignature;
    goto out;
  }

  Log(kDot2LogLevel_Event, "Success to parse Signed***CertProvisioningAck\n");

out:
  asn1_free_value(asn1_type_dot2SecuredScmsPDU, asn1_signed_ack);
  return ret;
}
