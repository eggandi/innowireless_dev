/** 
  * @file 
  * @brief 디코딩된 ffasn1c 정보를 파싱하여 일반 형식으로 반환하는 함수들을 구현한 파일
  * @date 2021-06-04 
  * @author gyun 
  */


// 라이브러리 의존 헤더 파일
#include "ffasn1-dot2-2021.h"

// 라이브러리 내부 헤더 파일
#include "dot2-internal.h"
#include "dot2-ffasn1c-inline.h"


/**
 * @brief ffasn1c 라이브러리를 이용하여 디코딩된 EccP256CurvePoint 필드 정보를 파싱하여 반환한다.
 * @param[in] from EccP256CurvePoint 필드 디코딩 정보
 * @param[out] to 타원곡선좌표가 저장될 구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseEccP256CurvePoint(const dot2EccP256CurvePoint *from, struct Dot2ECPoint *to)
{
  Log(kDot2LogLevel_Event, "Parse ECC P256 curve point\n");
  int ret;
  size_t size = DOT2_EC_256_KEY_LEN;
  switch (from->choice) {
    case dot2EccP256CurvePoint_x_only:
      to->u.point.form = kDot2ECPointForm_X_only;
      ret = dot2_ffasn1c_ParseOctetString(&(from->u.x_only), size, size, to->u.point.u.point);
      break;

    case dot2EccP256CurvePoint_compressed_y_0:
      to->u.point.form = kDot2ECPointForm_Compressed_y_0;
      ret = dot2_ffasn1c_ParseOctetString(&(from->u.compressed_y_0), size, size, to->u.point.u.point);
      break;

    case dot2EccP256CurvePoint_compressed_y_1:
      to->u.point.form = kDot2ECPointForm_Compressed_y_1;
      ret = dot2_ffasn1c_ParseOctetString(&(from->u.compressed_y_1), size, size, to->u.point.u.point);
      break;

    case dot2EccP256CurvePoint_uncompressedP256:
      to->u.point.form = kDot2ECPointForm_Uncompressed;
      ret = dot2_ffasn1c_ParseOctetString(&(from->u.uncompressedP256.x), size, size, to->u.point.u.xy.x);
      if (ret == (int)size) {
        ret = dot2_ffasn1c_ParseOctetString(&(from->u.uncompressedP256.y), size, size, to->u.point.u.xy.y);
      }
      break;

    default:
      Err("Fail to parse ECC P256 curve point  - invalid type %d\n", from->choice);
      ret = -kDot2Result_InvalidEccCurvePointType;
  }
  return ((ret >= 0) ? kDot2Result_Success : ret);
}


/**
 * @brief 서명정보에 대한 asn.1 디코딩정보를 파싱하여 공용 정보구조체에 저장한다.
 * @param[in] from 파싱할 디코딩정보
 * @param[out] to 파싱된 정보가 저장될 정보구조체 포인터
 * @retval 0: 성공
 * @retval 음수(-Dot2ResultCode): 실패
 */
int INTERNAL dot2_ffasn1c_ParseSignature(const dot2Signature *from, struct Dot2Signature *to)
{
  if (from->choice != dot2Signature_ecdsaNistP256Signature) {
    Err("Fail to parse sign - invalid type: %d\n", from->choice);
    return -kDot2Result_InvalidSignatureType;
  }
  int ret = dot2_ffasn1c_ParseEccP256CurvePoint(&(from->u.ecdsaNistP256Signature.rSig), &(to->R_r));
  if (ret == kDot2Result_Success) {
    const ASN1String *_from = &(from->u.ecdsaNistP256Signature.sSig);
    ret = dot2_ffasn1c_ParseOctetString(_from, DOT2_EC_256_KEY_LEN, DOT2_EC_256_KEY_LEN, to->s);
  }
  return ret;
}
