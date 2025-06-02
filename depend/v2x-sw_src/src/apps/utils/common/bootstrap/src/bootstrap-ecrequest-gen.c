/** 
  * @file 
  * @brief 부트스트래핑 동작 중 ECRequest 생성 관련 구현
  * @date 2022-07-17 
  * @author gyun 
  */


// 시스템 헤더 파일
#include <stdio.h>

// 유틸리티 헤더 파일
#include "bootstrap.h"


/**
 * @brief 등록인증서 발급요청문을 생성한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
int BOOTSTRAP_GenerateECRequest(void)
{
  printf("Generate EC request\n");
  int ret;
  struct Dot2ECRequestConstructParams params;
  params.time = 0;
  params.valid_period.start = g_cfg.gen.valid_start;
  params.valid_period.duration.type = g_cfg.gen.dur_type;
  params.valid_period.duration.duration = g_cfg.gen.dur;
  params.valid_region.region_num = g_cfg.gen.region_num;
  for (unsigned int i = 0; i < params.valid_region.region_num; i++) {
    params.valid_region.region[i] = g_cfg.gen.region[i];
  }
  params.permissions.num = g_cfg.gen.psid_num;
  for (unsigned int i = 0; i < params.permissions.num; i++) {
    params.permissions.psid[i] = g_cfg.gen.psid[i];
  }
  struct Dot2ECRequestConstructResult res = Dot2_ConstructECRequest(&params);
  if (res.ec_req) {
    printf("Success to Dot2_ConstructECRequest()\n");
    printf("  EC request(%u-bytes): ", res.ret);
    for (int i = 0; i < res.ret; i++) {
      printf("%02X", *(res.ec_req + i));
    }
    printf("\n  H8: ");
    for (int i = 0; i < 8; i++) {
      printf("%02X", *(res.ec_req_h8 + i));
    }
    printf("\n  Initial PrivKey: ");
    for (int i = 0; i < DOT2_EC_256_KEY_LEN; i++) {
      printf("%02X", res.init_priv_key.octs[i]);
    }
    printf("\n");
  } else {
    printf("Fail to Dot2_ConstructECRequest() : %d\n", res.ret);
    return -1;
  }

  /*
   * 생성된 EC request를 파일로 저장한다.
   */
  ret = BOOTSTARP_ExportFile(g_cfg.gen.ecreq_file, res.ec_req, res.ret);
  if (ret < 0) {
    goto out;
  }

  /*
   * 생성된 임시 개인키를 파일로 저장한다.
   */
  ret = BOOTSTARP_ExportFile(g_cfg.init_priv_key_file, res.init_priv_key.octs, DOT2_EC_256_KEY_LEN);

out:
  free(res.ec_req);
  return ret;
}
