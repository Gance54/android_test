#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <string.h>
#define LOGE(fmt, ...) fprintf(stderr, "[E][%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stdout, "[W][%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stdout, "[D][%s.%d]: " fmt "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stdout, "[I]" fmt "\n", ## __VA_ARGS__)

#endif // LOG_H
