/*
 * AHT20_STM32.h
 *
 *  Created on: Sep 20, 2024
 *      Author: Ganesh Thorat
 */

#ifndef APPLICATION_USER_CORE_AHT20_STM32_H_
#define APPLICATION_USER_CORE_AHT20_STM32_H_

#include "stm32h7xx.h"
#include "stm32h7xx_hal.h"
//#define AHT20_DEFAULT_ADDRESS  0x38 << 1  // Shifted for STM32 HAL (7-bit address)
#define AHT20_DEFAULT_ADDRESS  0x38  // AHT20 I2C Address
#define AHT20_INIT_CMD         0xBE0800
#define AHT20_MEASURE_CMD      0xAC3300
#define AHT20_RESET_CMD        0xBA
#define ERROR_DEVICE_CONNECTION_FAILED 1
#define WHD_SUCCESS 0
#define ERROR_CALIBRATION_FAILED 1
#define ERROR_DEVICE_CONNECT_FAILED 1

uint8_t AHT20_Init(I2C_HandleTypeDef *hi2c);
uint8_t AHT20_IsCalibrated(I2C_HandleTypeDef *hi2c);
uint8_t AHT20_Initialize(I2C_HandleTypeDef *hi2c);
uint8_t AHT20_TriggerMeasurement(I2C_HandleTypeDef *hi2c);
uint8_t AHT20_ReadData(I2C_HandleTypeDef *hi2c, uint32_t *humidity, uint32_t *temperature);
float AHT20_GetTemperature(uint32_t raw_temp);
float AHT20_GetHumidity(uint32_t raw_hum);
void AHT20_SoftReset(I2C_HandleTypeDef *hi2c);
void Read_TempAndHumiditySensor(I2C_HandleTypeDef *hi2c1,float *temp,float *hum);
void Read_MotionSensor(void);

#endif /* APPLICATION_USER_CORE_AHT20_STM32_H_ */
