#include "pipeline_optimizer.h"
#include <string.h>

void pipeline_init(pipeline_batch_t *pipeline, int batch_size) {
    memset(pipeline, 0, sizeof(pipeline_batch_t));
    pipeline->batch_size = batch_size > 0 ? batch_size : PIPELINE_BATCH_SIZE;
    pipeline->current_batch = 0;
    pipeline->ready = 0;
}

int pipeline_add_packet(pipeline_batch_t *pipeline, const char *packet, int size, uint32_t ip, uint16_t port) {
    if (pipeline->current_batch >= pipeline->batch_size) {
        pipeline->ready = 1;
        return 0;
    }
    
    memcpy(pipeline->packets[pipeline->current_batch], packet, size);
    pipeline->packet_sizes[pipeline->current_batch] = size;
    pipeline->target_ips[pipeline->current_batch] = ip;
    pipeline->target_ports[pipeline->current_batch] = port;
    pipeline->current_batch++;
    
    if (pipeline->current_batch >= pipeline->batch_size) {
        pipeline->ready = 1;
    }
    
    return 1;
}

int pipeline_flush(pipeline_batch_t *pipeline, raw_socket_t *sock) {
    if (!sock || pipeline->current_batch == 0) {
        return 0;
    }
    
    int sent = 0;
    for (int i = 0; i < pipeline->current_batch; i++) {
        int result = raw_socket_send(sock, 
                                      pipeline->packets[i], 
                                      pipeline->packet_sizes[i], 
                                      pipeline->target_ips[i], 
                                      pipeline->target_ports[i]);
        if (result >= 0) sent++;
    }
    
    pipeline_reset(pipeline);
    return sent;
}

int pipeline_is_ready(pipeline_batch_t *pipeline) {
    return pipeline->ready;
}

void pipeline_reset(pipeline_batch_t *pipeline) {
    pipeline->current_batch = 0;
    pipeline->ready = 0;
    memset(pipeline->packets, 0, sizeof(pipeline->packets));
    memset(pipeline->packet_sizes, 0, sizeof(pipeline->packet_sizes));
}
