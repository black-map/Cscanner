#include "adaptive_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define MIN_RATE 10
#define MAX_RATE 10000
#define LATENCY_SAMPLE_WINDOW 50
#define CONGESTION_THRESHOLD 0.3

static double latency_history[ADAPTIVE_SAMPLE_SIZE];
static int latency_index = 0;
static int latency_count = 0;

void adaptive_init(adaptive_engine_t *engine, adaptive_level_t initial_level) {
    memset(engine, 0, sizeof(adaptive_engine_t));
    engine->level = initial_level;
    engine->last_update = time(NULL);
    
    switch (initial_level) {
        case ADAPTIVE_SLOW:
            engine->current_rate = 50;
            break;
        case ADAPTIVE_NORMAL:
            engine->current_rate = 500;
            break;
        case ADAPTIVE_FAST:
            engine->current_rate = 2000;
            break;
        case ADAPTIVE_INSANE:
            engine->current_rate = 8000;
            break;
    }
    
    for (int i = 0; i < ADAPTIVE_SAMPLE_SIZE; i++) {
        latency_history[i] = 0.0;
    }
}

static double calculate_avg_latency() {
    if (latency_count == 0) return 0.0;
    
    double sum = 0.0;
    int count = latency_count < LATENCY_SAMPLE_WINDOW ? latency_count : LATENCY_SAMPLE_WINDOW;
    
    for (int i = 0; i < count; i++) {
        int idx = (latency_index - count + i + ADAPTIVE_SAMPLE_SIZE) % ADAPTIVE_SAMPLE_SIZE;
        if (latency_history[idx] > 0) {
            sum += latency_history[idx];
        }
    }
    
    return sum / count;
}

static double calculate_congestion_factor() {
    if (latency_count < 10) return 0.0;
    
    double mean = calculate_avg_latency();
    if (mean == 0) return 0.0;
    
    double variance = 0.0;
    int count = latency_count < LATENCY_SAMPLE_WINDOW ? latency_count : LATENCY_SAMPLE_WINDOW;
    
    for (int i = 0; i < count; i++) {
        int idx = (latency_index - count + i + ADAPTIVE_SAMPLE_SIZE) % ADAPTIVE_SAMPLE_SIZE;
        double diff = latency_history[idx] - mean;
        variance += diff * diff;
    }
    
    double stddev = sqrt(variance / count);
    return stddev / mean;
}

void adaptive_update(adaptive_engine_t *engine, double latency, int success) {
    latency_history[latency_index] = latency;
    latency_index = (latency_index + 1) % ADAPTIVE_SAMPLE_SIZE;
    latency_count++;
    
    if (success) {
        engine->success_count++;
    } else {
        engine->failure_count++;
    }
    
    time_t now = time(NULL);
    if (now - engine->last_update < 1) {
        return;
    }
    
    engine->avg_latency = calculate_avg_latency();
    engine->congestion_factor = calculate_congestion_factor();
    
    double failure_rate = (double)engine->failure_count / 
        (engine->success_count + engine->failure_count + 1);
    
    if (engine->congestion_factor > CONGESTION_THRESHOLD || failure_rate > 0.2) {
        engine->current_rate = (int)(engine->current_rate * 0.7);
        if (engine->current_rate < MIN_RATE) {
            engine->current_rate = MIN_RATE;
        }
    } else if (engine->avg_latency < 50 && failure_rate < 0.05) {
        engine->current_rate = (int)(engine->current_rate * 1.2);
        if (engine->current_rate > MAX_RATE) {
            engine->current_rate = MAX_RATE;
        }
    }
    
    engine->success_count = 0;
    engine->failure_count = 0;
    engine->last_update = now;
}

int adaptive_get_rate(adaptive_engine_t *engine) {
    return engine->current_rate;
}

adaptive_level_t adaptive_get_level(adaptive_engine_t *engine) {
    return engine->level;
}

void adaptive_adjust_timeout(adaptive_engine_t *engine, int *timeout) {
    double base_latency = engine->avg_latency > 0 ? engine->avg_latency : *timeout;
    
    if (engine->congestion_factor > CONGESTION_THRESHOLD) {
        *timeout = (int)(base_latency * 2.5);
    } else if (base_latency < 30) {
        *timeout = (int)(base_latency * 1.5);
    }
    
    if (*timeout < 100) *timeout = 100;
    if (*timeout > 30000) *timeout = 30000;
}

void adaptive_report_success(adaptive_engine_t *engine) {
    engine->success_count++;
}

void adaptive_report_failure(adaptive_engine_t *engine) {
    engine->failure_count++;
}
