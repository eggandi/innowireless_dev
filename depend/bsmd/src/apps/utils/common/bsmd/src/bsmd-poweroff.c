/**
 * @file
 * @brief Power off 관련 기능
 * @date 2022-10-02
 * @author gyun
 */


// 시스템 헤더 파일
#include <assert.h>
#include <stdio.h>
#include <string.h>

// 어플리케이션 헤더 파일
#include "include/bsmd.h"


/// Power off 감지용 GPIO 번호
#define BSMD_POWER_OFF_GPIO_NUM (358)
/// Power off 감지용 GPIO 번호 설정 파일
static const char *g_bsmd_power_off_gpio_export_file = "/sys/class/gpio/export";
/// Power off 감지용 GPIO 방향 설정 파일
static const char *g_bsmd_power_off_gpio_dir_file = "/sys/class/gpio/gpio358/direction";
/// Power off 감지용 GPIO 값 확인 파일
static const char *g_bsmd_power_off_gpio_val_file = "/sys/class/gpio/gpio358/value";
/// Power off 시 GPIO 입력 값
static const char g_bsmd_power_off_gpio_val = '0';


/**
 * @brief Power off 관련 기능을 초기화한다.
 */
void BSMD_InitPowerOffFunction(void)
{
  Log(kBSMDLogLevel_Event, "Initialize power off function\n");

  /*
   * Power off 감지용 GPIO를 초기화한다.
   */
  FILE *fp = fopen(g_bsmd_power_off_gpio_export_file, "w");
  assert(fp);
  fprintf(fp, "%u", BSMD_POWER_OFF_GPIO_NUM);
  fclose(fp);

  fp = fopen(g_bsmd_power_off_gpio_dir_file, "w");
  assert(fp);
  fprintf(fp, "in");
  fclose(fp);
}


/**
 * @brief Power off 여부를 확인한다.
 * @return Power off 여부 (true: Power off, false: Power on)
 */
bool BSMD_DetectPowerOff(void)
{
  bool power_off = false;
  char line[5];
  FILE *fp = fopen(g_bsmd_power_off_gpio_val_file, "r");
  assert(fp);
  fgets(line, sizeof(line), fp);
  if (line[0] == g_bsmd_power_off_gpio_val) {
    power_off = true;
  }
  fclose(fp);
  return power_off;
}
