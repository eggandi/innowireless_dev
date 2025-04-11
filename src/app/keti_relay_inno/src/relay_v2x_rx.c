/**
 * @file
 * @brief
 * @date 2025-04-09
 * @author dong
 */

#include "relay_v2x_rx.h"

/**
 * @brief LTE-V2X MSDU 수신처리 콜백함수. lteaccess 라이브러리에서 호출된다.
 * @param[in] msdu 수신된 MSDU (= WSM 헤더 + WSM body)
 * @param[in] msdu_size 수신된 MSDU의 크기
 */
extern void RELAY_INNO_V2X_RxMSDUCallback(const uint8_t *msdu, LTEV2XHALMSDUSize msdu_size, struct LTEV2XHALMSDURxParams rx_params)
{
  if(msdu_size > 0)
  {
    // 수신된 MSDU를 WSM 헤더와 WSM body로 나눈다.
		#if 0
    if(G_relay_inno_config.udp_enable)
    {
      int ret;
      ret = sendto(g_sockfd, msdu, msdu_size, 0, (struct sockaddr *)&g_v2x_addr, sizeof(g_v2x_addr));
      if(ret > 0)
      {
          //printf("Send Sucess. : %d\n", ret);
      }
    }
		#endif
  }
  return;
}

