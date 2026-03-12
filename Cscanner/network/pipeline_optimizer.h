#ifndef PIPELINE_OPTIMIZER_H
#define PIPELINE_OPTIMIZER_H

#include "../include/common.h"
#include "../include/raw_socket.h"

typedef struct {
    int batch_size;
    int current_batch;
    char packets[PIPELINE_BATCH_SIZE][256];
    int packet_sizes[PIPELINE_BATCH_SIZE];
    uint32_t target_ips[PIPELINE_BATCH_SIZE];
    uint16_t target_ports[PIPELINE_BATCH_SIZE];
    int ready;
} pipeline_batch_t;

void pipeline_init(pipeline_batch_t *pipeline, int batch_size);
int pipeline_add_packet(pipeline_batch_t *pipeline, const char *packet, int size, uint32_t ip, uint16_t port);
int pipeline_flush(pipeline_batch_t *pipeline, raw_socket_t *sock);
int pipeline_is_ready(pipeline_batch_t *pipeline);
void pipeline_reset(pipeline_batch_t *pipeline);

#endif
