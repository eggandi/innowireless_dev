#include "relay_main.h"
#include "relay_config.h"
#include "relay_v2x.h"
#include "relay_v2x_j2735_bsm.h"
#include "relay_v2x_dot2.h"
/**
 * @brief 시그널 셋업
 * @details 시스템 시그널 제어 및 종료 시그널 핸들러를 등록한다.
 * @param void
 * @return void
 */
static void RELAY_INNO_Main_Signal_Set();

/**
 * @brief 시그널 핸들러
 * @details 시그널 핸들러
 * @param signo 시그널 번호
 * @return void
 */
static void RELAY_INNO_Main_Signal_Handler(int signo);

pthread_t g_thread_gnss;

int main()//(int argc, char *argv[])
{
  int ret;
	// 
  ret = RELAY_INNO_Config_Setup_Configuration_Read(&G_relay_inno_config);
  if(ret < 0)
  {
    _DEBUG_PRINT("Configuration read failed.\n");
    return -1;
  } else{
    _DEBUG_PRINT("Configuration read success.\n");
  }
  RELAY_INNO_Main_Signal_Set();

  ret = RELAY_INNO_V2X_Init();
  if(ret < 0)
  {
    _DEBUG_PRINT("V2X initialization failed.\n");
    goto out;
  }else{
    _DEBUG_PRINT("V2X initialization success.\n");
  }
	
	ret = RELAY_INNO_V2X_Dot2_Security_Init();
	if(ret < 0)
	{
		_DEBUG_PRINT("V2X security initialization failed.\n");
		goto out;
	}else{
		_DEBUG_PRINT("V2X security initialization success.\n");
	}

	ret = RELAY_INNO_Gnss_Init_Gnssata(&g_thread_gnss);
	if(ret < 0)
	{
		_DEBUG_PRINT("Gnss initialization failed.\n");
		goto out;
	}else{
		_DEBUG_PRINT("Gnss initialization success.\n");
	}
	struct itimerspec itval;
  int msec = 10;
  
	int32_t time_fd = timerfd_create (CLOCK_REALTIME, 0);
  itval.it_value.tv_sec = 1;
  itval.it_value.tv_nsec = 0;
  itval.it_interval.tv_sec = 0 + (msec / 1000);
  itval.it_interval.tv_nsec = (msec % 1000) * 1e6;
  timerfd_settime(time_fd, TFD_TIMER_ABSTIME, &itval, NULL);

  uint64_t res;
	uint32_t time_tick_10ms = 0;
	G_relay_inno_config.v2x.tx_running = true;
  while(1)
  {
    ret = read(time_fd, &res, sizeof(res));
		time_tick_10ms = (time_tick_10ms + 1) % 0x10000000;
    if(ret < 0)
    {
      _DEBUG_PRINT("read");
      break;
    }
		switch(time_tick_10ms % 100)
		{
			default:
			{
				break;
			}
			case 100: //1초마다 호출
			{
			}
			case 10: //100ms마다 호출
			{
				if(G_relay_inno_config.v2x.tx_running == true)
				{
					ret = RELAY_INNO_V2X_Tx_J2735_BSM(NULL);
					if(ret < 0)
					{
						_DEBUG_PRINT("V2X Tx BSM failed.\n");
					}else{
						_DEBUG_PRINT("V2X Tx BSM success.\n");
					}

				}
				break;
			}
		}
  }
out:
  RELAY_INNO_Main_Signal_Handler(SIGINT);
  return 0;
}

static void RELAY_INNO_Main_Signal_Set()
{
  /*
  * 종료 시에 반드시 LAL_Close()가 호출되어야 하므로, 종료 시그널 핸들러를 등록한다.
  */
  struct sigaction sig_action;
  sig_action.sa_handler = RELAY_INNO_Main_Signal_Handler;
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = 0;

  sigaction(SIGINT, &sig_action, NULL);
  sigaction(SIGHUP, &sig_action, NULL);
  sigaction(SIGTERM, &sig_action, NULL);
  sigaction(SIGSEGV, &sig_action, NULL);
  return;
}

static void RELAY_INNO_Main_Signal_Handler(int signo)
{
  switch(signo)
  {
    case SIGINT:
    case SIGTERM:
    case SIGSEGV:
    case SIGHUP:
    {
      _DEBUG_PRINT("Signal %d received. Exit.\n", signo);
      (void)signo;
      G_relay_inno_config.v2x.tx_running = false;
      exit(0);
      system("killall "PROJECT_NAME);
      break;
    }
    default:
    {
      exit(0);
      system("killall "PROJECT_NAME);
      break;
    }
  }
  return;
}