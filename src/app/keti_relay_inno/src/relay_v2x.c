/**
 * @file
 * @brief
 * @date 2025-04-09
 * @author dong
 */

#include "relay_v2x.h"

/**
 * @brief V2X 라이브러리들을 초기화한다.
 * @retval 0: 성공
 * @retval -1: 실패
 */
API int RELAY_INNO_V2X_Init(void)
{
  LTEV2XHALLogLevel hal_log_level = (LTEV2XHALLogLevel ) G_relay_inno_config.v2x.lib_dbg;

  // LTEV2X 접속계층 라이브러리 초기화하고 패킷수신콜백함수를 등록한다.
  int ret = LTEV2XHAL_Init(hal_log_level, G_relay_inno_config.v2x.dev_name);
  if (ret < 0) {
    _DEBUG_PRINT("Fail to initialize ltev2x-hal library - LTEV2XHAL_Init() failed: %d\n", ret);
    return -1;
  }
  LTEV2XHAL_RegisterCallbackProcessMSDU(RELAY_INNO_V2X_RxMSDUCallback);
	
  ret = Dot2_Init(hal_log_level, 100, NULL, 5);
  if (ret < 0) {
    Err("Fail to initialize dot2 library - Dot2_Init() failed: %d\n", ret);
    goto out;
  }else{
		_DEBUG_PRINT("Success to initialize dot2 library\n");

	}
	
#if 0
  if(G_relay_inno_config.udp_enable)
  {
    g_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sockfd < 0) {
        exit(EXIT_FAILURE);
    }
    int flags = fcntl(g_sockfd, F_GETFL, 0);
    fcntl(g_sockfd, F_SETFL, flags | O_NONBLOCK);

    struct linger solinger = { 1, 0 };
    setsockopt(g_sockfd, SOL_SOCKET, SO_LINGER, &solinger, sizeof(struct linger));

    memset(&g_v2x_addr, 0, sizeof(g_v2x_addr));
    g_v2x_addr.sin_family = AF_INET;
    g_v2x_addr.sin_port = htons(G_relay_inno_config.udp_port_v2x);
    g_v2x_addr.sin_addr.s_addr = inet_addr(G_relay_inno_config.udp_ip_str);
  }
#endif
  _DEBUG_PRINT("Success to initialize V2X library\n");
  return 0;
}

extern int RELAY_INNO_V2X_Psid_Filter(unsigned int psid)
{
	int ret;
	switch(psid)
	{
    case 32:{	goto add;	break;}//BSM
		case 135:{	goto add;	break;}//WSA
		case 82056:{	goto add;	break;}//MAP
		case 82055:{	goto add;	break;}//SPAT
		case 82051:{	goto out;	break;}//PVD
		case 82053:{	goto out;	break;}//RSA
		case 82057:{	goto add;	break;}//RTCM
		case 82054:{	goto add;	break;}//TIM
		default :
		{
add:
			ret = Dot3_AddWSR(psid);
      _DEBUG_PRINT("Success to Add WSR(psid: %u)\n", psid);
			break;
		}
	}		
	if (ret < 0) {
		_DEBUG_PRINT("Fail to add WSR(psid: %u) - %d\n", psid, ret);
		return -1;
	}
out:
	return 0;

}