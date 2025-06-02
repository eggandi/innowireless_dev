/** 
  * @file 
  * @brief ffasn1c 관련 인라인 함수를 정의한 헤더 파일
  * @date 2021-09-05 
  * @author gyun 
  */

#ifndef V2X_SW_DOT2_FFASN1C_INLINE_H
#define V2X_SW_DOT2_FFASN1C_INLINE_H


// 시스템 헤더 파일
#include <stdint.h>
#include <string.h>

// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 헤더 파일
#include "dot2-2016/dot2-types.h"

// 라이브러리 내부 헤더 파일


/**
 * @brief ffasn1c 라이브러리를 이용하여 인증서를 디코딩한다.
 * @param[in] cert 디코딩할 인증서 (인코딩 바이트열)
 * @param[in] cert_size 디코딩할 인증서의 크기
 * @param[out] err 실패 시 에러값(-Dot2ResultCode)이 저장될 변수 포인터
 * @return 디코딩된 인증서정보(asn.1 정보구조체) 구조체 포인터. 동적할당된 정보이므로 사용 후 asn1_free_value()를 통해 해제되어야 한다.
 * @retval NULL: 실패
 */
static inline dot2Certificate * dot2_ffasn1c_DecodeCertificate(const uint8_t *cert, Dot2CertSize cert_size, int *err)
{
  dot2Certificate *cert_data = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&cert_data, asn1_type_dot2Certificate, cert, cert_size, &err1);
  if (decoded_size < 0) {
    *err = -kDot2Result_ASN1_DecodeCertificate;
    return NULL;
  }
  return cert_data;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 OctetString 필드 정보를 파싱하여 반환한다.
 * @param[in] from OctetString 필드 디코딩 정보
 * @param[in] min_size 최소길이
 * @param[in] max_size 최대길이(=to 버퍼의 길이를 사용한다)
 * @param[out] to 바이트열이 저장될 버퍼 포인터
 * @retval 0 이상: 반환되는 바이트열의 길이
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_ParseOctetString(const ASN1String *from, size_t min_size, size_t max_size, uint8_t *to)
{
  if ((from->len < min_size) ||
      (from->len > max_size)) {
    return -kDot2Result_ASN1_InvalidOctetStringLength;
  }
  memcpy(to, from->buf, from->len);
  return (int)(from->len);
}


/**
 * @brief ffas1nc ASN1String 필드를 채운다.
 * @param[in] from 채울 바이트열
 * @param[in] from_len 채울 바이트열의 길이
 * @param[out] to 값이 채워질 ASN1String 정보구조체 포인터 (ASN.1 context)
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_FillASN1String(const uint8_t *from, size_t from_len, struct ASN1String *to)
{
  int ret = -kDot2Result_NoMemory;
  if ((from == NULL) || (from_len == 0)) { // 0 바이트 octet string
    to->len = 0;
    ret = kDot2Result_Success;
  } else {
    to->len = from_len;
    to->buf = (uint8_t *)malloc(from_len);
    if (to->buf) {
      memcpy(to->buf, from, to->len);
      ret = kDot2Result_Success;
    }
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 Certificate 필드를 인코딩한다. (Certificate 내 필드는 채워져 있어야 한다)
 * @param[in] asn1_cert 인코딩할 Certificate 정보구조체 형식
 * @param[out] encoded_size 인코딩된 인증서데이터의 길이가 저장될 변수 포인터
 * @return 인코딩된 인증서 데이터 포인터: 성공
 * @retval NULL: 실패
 *
 * 반환된 인증서데이터는 free() 함수를 통해 해제되어야 한다.
 */
static inline uint8_t * dot2_ffasn1c_EncodeCertificate(const dot2Certificate *asn1_cert, size_t *encoded_size)
{
  uint8_t *buf, *ret = NULL;
  asn1_ssize_t size = asn1_oer_encode(&buf, asn1_type_dot2Certificate, asn1_cert);
  if ((size > 0) &&
      (buf != NULL)) {
    *encoded_size = (size_t)size;
    ret = buf;
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 SPDU를 COER 디코딩한다.
 * @param[in] spdu 디코딩할 SPDU
 * @param[in] spdu_size 디코딩할 SPDU의 길이
 * @return SPDU 디코딩 정보 구조체 포인터
 * @retval NULL: 실패
 *
 * 반환된 정보는 free() 함수를 통해 해제되어야 한다.
 */
static inline struct dot2Ieee1609Dot2Data * dot2_ffasn1c_DecodeSPDU(const uint8_t *spdu, size_t spdu_size)
{
  struct dot2Ieee1609Dot2Data *asn1_spdu = NULL;
  ASN1Error err;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn1_spdu, asn1_type_dot2Ieee1609Dot2Data, spdu, spdu_size, &err);
  if (decoded_size < 0) {
    return NULL;
  }
  return asn1_spdu;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 UnsecuredData 필드 정보를 파싱하여 반환한다.
 * @param[in] asn1_data UnsecuredData 필드 디코딩 정보
 * @param[out] parsed 파싱정보가 저장될 패킷파싱데이터 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_ParseUnsecuredData(const dot2Opaque *asn1_data, struct V2XPacketParseData *parsed)
{
  int ret = -kDot2Result_NoMemory;
  parsed->ssdu_size = 0;
  if ((asn1_data->buf == NULL) || (asn1_data->len == 0)) {
    ret = kDot2Result_Success;
  } else {
    parsed->ssdu = (uint8_t *)calloc(1, asn1_data->len);
    if (parsed->ssdu) {
      parsed->ssdu_size = asn1_data->len;
      memcpy(parsed->ssdu, asn1_data->buf, parsed->ssdu_size);
      ret = kDot2Result_Success;
    }
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 U64 형식의 ASN1Integer 필드를 파싱하여 반환한다.
 * @param[in] from ASN1Integer 필드 디코딩 정보
 * @return 파싱된 값
 */
static inline uint64_t dot2_ffasn1c_ParseU64ASN1Integer(const ASN1Integer *from)
{
  uint64_t ret = 0ULL;
  if (from->len > 0) {
    uint64_t low, high = 0ULL;
    low = *(from->data);
    if (from->len >= 2) {
      high = *(from->data + 1);
    }
    ret = ((high << 32) | low);
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 PSID 필드 정보를 파싱하여 반환한다.
 * @param[in] from PSID 필드 디코딩 정보
 * @return 파싱된 PSID 값
 */
static inline Dot2PSID dot2_ffasn1c_ParsePSID(const dot2Psid *from)
{
  return (Dot2PSID)dot2_ffasn1c_ParseU64ASN1Integer(from);
}


/**
 * @brief dot2SecuredScmsPDU를 인코딩한다.
 * @param[in] asn1_pdu 인코딩할 dot2SecuredScmsPDU asn.1 정보 구조체
 * @param[out] encoded_size 인코딩된 데이터의 길이가 저장될 변수 포인터
 * @return 인코딩된 데이터 포인터
 * @retval NULL: 실패
 */
static inline uint8_t * dot2_ffasn1c_EncodeSecuredScmsPDU(dot2SecuredScmsPDU *asn1_pdu, size_t *encoded_size)
{
  uint8_t *buf, *ret = NULL;
  asn1_ssize_t size = asn1_oer_encode(&buf, asn1_type_dot2SecuredScmsPDU, asn1_pdu);
  if ((size > 0) &&
      (buf != NULL)) {
    *encoded_size = (size_t)size;
    ret = buf;
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 ToBeSignedData 필드를 인코딩한다. (ToBeSignedData 내 필드는 채워져 있어야 한다)
 * @param[in] asn1_tbs 인코딩할 ToBeSignedData 정보구조체 형식
 * @param[out] encoded_size 인코딩된 ToBeSignedData의 길이가 저장될 변수 포인터
 * @return 인코딩된 ToBeSignedData 데이터 포인터: 성공 (사용후 free()해 주어야 한다)
 * @retval NULL: 실패
 */
static inline uint8_t * dot2_ffasn1c_EncodeToBeSignedData(const dot2ToBeSignedData *asn1_tbs, size_t *encoded_size)
{
  uint8_t *buf, *ret = NULL;
  asn1_ssize_t size = asn1_oer_encode(&buf, asn1_type_dot2ToBeSignedData, asn1_tbs);
  if ((size > 0) &&
      (buf != NULL)) {
    *encoded_size = (size_t)size;
    ret = buf;
  }
  return ret;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 SecuredScmsPDU를 디코딩한다.
 * @param[in] pdu 디코딩할 SecuredScmsPDU 바이트열
 * @param[in] pdu_size 디코딩할 SecuredScmsPDU 바이트열의 길이
 * @return 디코딩된 SecuredScmsPDU 정보(asn.1 정보구조체) 구조체 포인터. 사용 후 asn1_free_value()를 통해 해제되어야 한다.
 * @retval NULL: 실패
 */
static inline dot2SecuredScmsPDU * dot2_ffasn1c_DecodeSecuredScmsPDU(const uint8_t *pdu, Dot2SPDUSize pdu_size)
{
  dot2SecuredScmsPDU *asn1_pdu = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn1_pdu, asn1_type_dot2SecuredScmsPDU, pdu, pdu_size, &err1);
  if (decoded_size < 0) {
    return NULL;
  }
  return asn1_pdu;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 ScmsPDU를 디코딩한다.
 * @param[in] pdu 디코딩할 ScmsPDU 바이트열
 * @param[in] pdu_size 디코딩할 ScmsPDU 바이트열의 길이
 * @return 디코딩된 ScmsPDU 정보(asn.1 정보구조체) 구조체 포인터. 사용 후 asn1_free_value()를 통해 해제되어야 한다.
 * @retval NULL: 실패
 */
static inline dot2ScmsPDU * dot2_ffasn1c_DecodeScmsPDU(const uint8_t *pdu, Dot2SPDUSize pdu_size)
{
  dot2ScmsPDU *asn1_pdu = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn1_pdu, asn1_type_dot2ScmsPDU, pdu, pdu_size, &err1);
  if (decoded_size < 0) {
    return NULL;
  }
  return asn1_pdu;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 PlaintextCertificateResponse를 디코딩한다.
 * @param[in] pdu 디코딩할 PlaintextCertificateResponse 바이트열
 * @param[in] pdu_size 디코딩할 PlaintextCertificateResponse 바이트열의 길이
 * @return 디코딩된 PlaintextCertificateResponse 정보(asn.1 정보구조체) 구조체 포인터.
 *         사용 후 asn1_free_value()를 통해 해제되어야 한다.
 * @retval NULL: 실패
 */
static inline dot2PlaintextCertificateResponse *
dot2_ffasn1c_DecodePlaintextCertificateResponse(const uint8_t *pdu, Dot2SPDUSize pdu_size)
{
  dot2PlaintextCertificateResponse *asn1_pdu = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn1_pdu,
                                              asn1_type_dot2PlaintextCertificateResponse,
                                              pdu,
                                              pdu_size,
                                              &err1);
  if (decoded_size < 0) {
    return NULL;
  }
  return asn1_pdu;
}


/**
 * @brief ffasn1c 라이브러리를 이용하여 ToBeSignedEncryptedCertificateResponse를 디코딩한다.
 * @param[in] pdu 디코딩할 ToBeSignedEncryptedCertificateResponse 바이트열
 * @param[in] pdu_size 디코딩할 ToBeSignedEncryptedCertificateResponse 바이트열의 길이
 * @return 디코딩된 ToBeSignedEncryptedCertificateResponse 정보(asn.1 정보구조체) 구조체 포인터.
 *         사용 후 asn1_free_value()를 통해 해제되어야 한다.
 * @retval NULL: 실패
 */
static inline dot2ToBeSignedEncryptedCertificateResponse *
dot2_ffasn1c_DecodeToBeSignedEncryptedCertificateResponse(const uint8_t *pdu, Dot2SPDUSize pdu_size)
{
  dot2ToBeSignedEncryptedCertificateResponse *asn1_pdu = NULL;
  ASN1Error err1;
  asn1_ssize_t decoded_size = asn1_oer_decode((void **)&asn1_pdu,
                                              asn1_type_dot2ToBeSignedEncryptedCertificateResponse,
                                              pdu,
                                              pdu_size,
                                              &err1);
  if (decoded_size < 0) {
    return NULL;
  }
  return asn1_pdu;
}


/**
 * @brief PublicVerificationKey 필드를 채운다.
 * @param[in] from 공개키
 * @param[out] to 공개키를 채울 asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_FillPublicVerificationKey(const struct Dot2ECPublicKey *from, dot2PublicVerificationKey *to)
{
  int ret;
  size_t len = DOT2_EC_256_KEY_LEN;
  to->choice = dot2PublicVerificationKey_ecdsaNistP256;
  if ((from->u.octs[DOT2_EC_256_PUB_KEY_LEN - 1] & 1) == 1) {
    to->u.ecdsaNistP256.choice = dot2EccP256CurvePoint_compressed_y_1;
    ret = dot2_ffasn1c_FillASN1String(from->u.point.u.xy.x, len, &(to->u.ecdsaNistP256.u.compressed_y_1));
  } else {
    to->u.ecdsaNistP256.choice = dot2EccP256CurvePoint_compressed_y_0;
    ret = dot2_ffasn1c_FillASN1String(from->u.point.u.xy.x, len, &(to->u.ecdsaNistP256.u.compressed_y_0));
  }
  return ret;
}


/**
 * @brief PublicEncryptionKey 필드를 채운다.
 * @param[in] from 공개키
 * @param[out] to 공개키를 채울 asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_FillPublicEncryptionKey(const struct Dot2ECPublicKey *from, dot2PublicEncryptionKey *to)
{
  int ret;
  size_t len = DOT2_EC_256_KEY_LEN;
  to->supportedSymmAlg = dot2SymmAlgorithm_aes128Ccm;
  to->publicKey.choice = dot2BasePublicEncryptionKey_eciesNistP256;
  if ((from->u.octs[DOT2_EC_256_PUB_KEY_LEN - 1] & 1) == 1) {
    to->publicKey.u.eciesNistP256.choice = dot2EccP256CurvePoint_compressed_y_1;
    ret = dot2_ffasn1c_FillASN1String(from->u.point.u.xy.x, len, &(to->publicKey.u.eciesNistP256.u.compressed_y_1));
  } else {
    to->publicKey.u.eciesNistP256.choice = dot2EccP256CurvePoint_compressed_y_0;
    ret = dot2_ffasn1c_FillASN1String(from->u.point.u.xy.x, len, &(to->publicKey.u.eciesNistP256.u.compressed_y_0));
  }
  return ret;
}


/**
 * @brief UnsignedButterflyParams 필드를 채운다.
 * @param[in] pub_key caterpillar 공개키
 * @param[in] exp_key 확장함수키
 * @param[out] to 공개키를 채울 asn.1 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
static inline int dot2_ffasn1c_FillUnsignedButterflyParams(
  const struct Dot2ECPublicKey *pub_key,
  const struct Dot2AESKey *exp_key,
  dot2UnsignedButterflyParams *to)
{
  int ret;

  /*
   * caterpillar 공개키를 채운다.
   */
  size_t len = DOT2_EC_256_KEY_LEN;
  if ((pub_key->u.octs[DOT2_EC_256_PUB_KEY_LEN - 1] & 1) == 1) {
    to->seed_key.choice = dot2EccP256CurvePoint_compressed_y_1;
    ret = dot2_ffasn1c_FillASN1String(pub_key->u.point.u.xy.x, len, &(to->seed_key.u.compressed_y_1));
  } else {
    to->seed_key.choice = dot2EccP256CurvePoint_compressed_y_0;
    ret = dot2_ffasn1c_FillASN1String(pub_key->u.point.u.xy.x, len, &(to->seed_key.u.compressed_y_0));
  }
  if (ret < 0) {
    return ret;
  }

  /*
   * 확장함수 키를 채운다.
   */
  return dot2_ffasn1c_FillASN1String(exp_key->octs, DOT2_AES_128_LEN, &(to->expansion));
}


#endif //V2X_SW_DOT2_FFASN1C_INLINE_H
