#if 1
/*
 * SensorData.c
 *
 *  Created on: Sep 20, 2024
 *      Author: Ganesh Thorat
 */
#include "stm32h7xx.h"
#include "stm32h7xx_hal.h"
#include<stdio.h>
#include "AHT20_STM32.h"
#include "main.h"


extern RTC_HandleTypeDef hrtc;
#define ERROR_DEVICE_NOT_CONNECTED -1
#define ERROR_DEVICE_CALIBRATION_FAILED -2

uint8_t AHT20_Init(I2C_HandleTypeDef *hi2c)
{

    HAL_Delay(400);  // Wait for 40 ms after power-on

    if (HAL_I2C_IsDeviceReady(hi2c, AHT20_DEFAULT_ADDRESS << 1, 2, 100) != HAL_OK)
    {
        return ERROR_DEVICE_CONNECT_FAILED;  // Device not connected
    }

    if (!AHT20_IsCalibrated(hi2c))
    {
        AHT20_Initialize(hi2c);
        AHT20_TriggerMeasurement(hi2c);
        HAL_Delay(75);  // Wait for measurement
        if (!AHT20_IsCalibrated(hi2c))
            return ERROR_CALIBRATION_FAILED;  // Calibration failed
    }

    return WHD_SUCCESS;  // Initialization successful
}

uint8_t AHT20_IsCalibrated(I2C_HandleTypeDef *hi2c)
{
    uint8_t status = 0;
   if( HAL_I2C_Master_Receive(hi2c, AHT20_DEFAULT_ADDRESS << 1, &status, 1, 100)!= HAL_OK)
	    {
	        return ERROR_DEVICE_CONNECTION_FAILED;  // Device not connected
	    }
   HAL_Delay(400);
    return (status & (1 << 3));  // Check the calibrated bit
}

uint8_t AHT20_Initialize(I2C_HandleTypeDef *hi2c)
{
    uint8_t init_cmd[3] = {0xBE, 0x08, 0x00};
   if( HAL_I2C_Master_Transmit(hi2c, AHT20_DEFAULT_ADDRESS << 1, init_cmd, 3, 100)!= HAL_OK)
   {
       return ERROR_DEVICE_CONNECTION_FAILED;  // Device not connected
   }
   HAL_Delay(400);
   return WHD_SUCCESS;
}

uint8_t AHT20_TriggerMeasurement(I2C_HandleTypeDef *hi2c)
{
    uint8_t measure_cmd[3] = {0xAC, 0x33, 0x00};
    if(HAL_I2C_Master_Transmit(hi2c, AHT20_DEFAULT_ADDRESS << 1, measure_cmd, 3, 100)!= HAL_OK)
    {
        return ERROR_DEVICE_CONNECTION_FAILED;  // Device not connected
    }
    HAL_Delay(400);
    return WHD_SUCCESS;
}

uint8_t AHT20_ReadData(I2C_HandleTypeDef *hi2c, uint32_t *humidity, uint32_t *temperature)
{
    uint8_t data[6];
   if( HAL_I2C_Master_Receive(hi2c, AHT20_DEFAULT_ADDRESS << 1, data, 6, 100)!= HAL_OK)
   {
       return ERROR_DEVICE_CONNECTION_FAILED;  // Device not connected
   }
   HAL_Delay(400);
    // Process the humidity
    *humidity = ((uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3]) >> 4;
    // Process the temperature
    *temperature = ((uint32_t)data[3] << 16 | (uint32_t)data[4] << 8 | data[5]) & 0xFFFFF;
    return WHD_SUCCESS;
}
float AHT20_GetTemperature(uint32_t raw_temp)
{
    return ((float)raw_temp / 1048576) * 200 - 50;

}

float AHT20_GetHumidity(uint32_t raw_hum)
{
    return ((float)raw_hum / 1048576) * 100;
}

void AHT20_SoftReset(I2C_HandleTypeDef *hi2c)
{
    uint8_t reset_cmd = 0xBA;
    if(HAL_I2C_Master_Transmit(hi2c, AHT20_DEFAULT_ADDRESS << 1, &reset_cmd, 1, 100)!= HAL_OK)
    {
        return ERROR_DEVICE_CONNECTION_FAILED;  // Device not connected
    }
    return WHD_SUCCESS;
}

void Read_TempAndHumiditySensor(I2C_HandleTypeDef *hi2c1,float *temp,float *hum)
{
	uint32_t humidity = 0;
	      uint32_t temperature = 0;

	      if (AHT20_Init(hi2c1)==0)
	      {
	    	  	  AHT20_TriggerMeasurement(hi2c1);
	              HAL_Delay(75);

	              AHT20_ReadData(hi2c1, &humidity, &temperature);
	              get_time_date();
	              *temp = AHT20_GetTemperature(temperature);
	              printf("temp = %f \n\r",*temp);
	              *hum = AHT20_GetHumidity(humidity);
	              printf("hum= %f \n\r",*hum);

	              // Use tempC and relHum values in your application
	              HAL_Delay(1000);

	      }
}
void get_time_date(void)
{
  RTC_DateTypeDef gDate;
  RTC_TimeTypeDef gTime;

  /* Get the RTC current Time */
  HAL_RTC_GetTime(&hrtc, &gTime, RTC_FORMAT_BIN);
  /* Get the RTC current Date */
  HAL_RTC_GetDate(&hrtc, &gDate, RTC_FORMAT_BIN);

  /* Display time Format: hh:mm:ss */
  printf("%02d:%02d:%02d\n\r",gTime.Hours, gTime.Minutes, gTime.Seconds);

  /* Display date Format: dd-mm-yyyy */
  printf("%02d-%02d-%2d\n\r",gDate.Date, gDate.Month, 2000 + gDate.Year);
}

#endif
