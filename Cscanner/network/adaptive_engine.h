#ifndef ADAPTIVE_ENGINE_H
#define ADAPTIVE_ENGINE_H

#include "../include/common.h"

void adaptive_init(adaptive_engine_t *engine, adaptive_level_t initial_level);
void adaptive_update(adaptive_engine_t *engine, double latency, int success);
int adaptive_get_rate(adaptive_engine_t *engine);
adaptive_level_t adaptive_get_level(adaptive_engine_t *engine);
void adaptive_adjust_timeout(adaptive_engine_t *engine, int *timeout);
void adaptive_report_success(adaptive_engine_t *engine);
void adaptive_report_failure(adaptive_engine_t *engine);

#endif
