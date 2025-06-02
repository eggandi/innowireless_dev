/**
 * @file
 * @date 2019-08-17
 * @author gyun
 * @brief ffasn1c 라이브러리 기반 공통 인코딩/디코딩 관련 기능 구현 파일
 */


// 라이브러리 의존 헤더 파일
#include "asn1defs_int.h"
#include "ffasn1-dot3-2016.h"

// 라이브러리 내부 헤더 파일
#include "dot3-internal.h"


/**
 * @brief ASN.1 인코딩을 위해 VarLengthNumber(Psid) 정보구조체를 채운다.
 * @param[in] psid 인코딩할 psid 값
 * @param[out] var_len_num 정보를 채울 정보구조체의 포인터를 전달한다.
 * @retval 0: 성공
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_ffasn1c_FillVarLengthNumber(Dot3PSID psid, dot3VarLengthNumber *var_len_num)
{
  Log(kDot3LogLevel_Event, "Fill VarLengthNumber - PSID: %u\n", psid);

  /*
   * Psid 값의 범위에 따라 p-encoded Psid 의 길이를 결정한다.
   */
  uint32_t p_encoded_psid_len;
  if (psid <= 127) {
    p_encoded_psid_len = 1;
  } else if (psid <= 16511) {
    p_encoded_psid_len = 2;
  } else if (psid <= 2113663) {
    p_encoded_psid_len = 3;
  } else if (psid <= 270549119) {
    p_encoded_psid_len = 4;
  } else {
    Err("Fail to fill VarLengthNumber(PSID) - invalid PSID %u\n", psid);
    return -kDot3Result_InvalidPSID;
  }

  /*
   * p-encoded Psid 값의 길이에 맞게 VarLengthNumber 정보구조체를 채운다.
   */
  if (p_encoded_psid_len == 1) {
    var_len_num->choice = dot3VarLengthNumber_content;
    var_len_num->u.content = (int)psid;
  }
  else {
    var_len_num->choice = dot3VarLengthNumber_extension;
    if (p_encoded_psid_len == 2) {
      var_len_num->u.extension.choice = dot3Ext1_content;
      var_len_num->u.extension.u.content = (int)psid;
    }
    else {
      var_len_num->u.extension.choice = dot3Ext1_extension;
      if (p_encoded_psid_len == 3) {
        var_len_num->u.extension.u.extension.choice = dot3Ext2_content;
        var_len_num->u.extension.u.extension.u.content = (int)psid;
      }
      else {
        var_len_num->u.extension.u.extension.choice = dot3Ext2_extension;
        var_len_num->u.extension.u.extension.u.extension = (int)psid;
      }
    }
  }

  Log(kDot3LogLevel_Event, "Success to fill VarLengthNumber\n");
  return kDot3Result_Success;
}


/**
 * @brief 디코딩된 VarLengthNumber 정보를 파싱하여 PSID 를 반환한다.
 * @param[in] var_len_num 파싱할 VarLengthNumber 정보구조체의 주소를 전달한다.
 * @retval 0 이상: 파싱된 PSID
 * @retval 음수(-Dot3ResultCode): 실패
 */
int INTERNAL dot3_ffasn1c_ParseVarLengthNumber(const dot3VarLengthNumber *var_len_num)
{
  Log(kDot3LogLevel_Event, "Parse VarLengthNumber\n");

  int psid;
  if (var_len_num->choice == dot3VarLengthNumber_content) {
    psid = var_len_num->u.content;
  } else if (var_len_num->choice == dot3VarLengthNumber_extension) {
    const struct dot3Ext1 *ext1 = &var_len_num->u.extension;
    if (ext1->choice == dot3Ext1_content) {
      psid = ext1->u.content;
    } else if (ext1->choice == dot3Ext1_extension) {
      const struct dot3Ext2 *ext2 = &ext1->u.extension;
      if (ext2->choice == dot3Ext2_content) {
        psid = ext2->u.content;
      } else if (ext2->choice == dot3Ext2_extension) {
        psid = ext2->u.extension;
      } else {
        return -kDot3Result_InvalidPSIDFormat;
      }
    } else {
      return -kDot3Result_InvalidPSIDFormat;
    }
  } else {
    return -kDot3Result_InvalidPSIDFormat;
  }

  Log(kDot3LogLevel_Event, "Success to parse VarLengthNumber - psid: %d\n", psid);
  return psid;
}
