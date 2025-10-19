#ifndef ETCS_PACKETS_H
#define ETCS_PACKETS_H

#include <stdint.h>

#include "etcs-common.h"

void init_packet_info(void);

void etcs_register_packets(int proto);

const etcs_packet_t *etcs_packet_to_track_by_nid_packet(uint8_t nid_packet);

const etcs_packet_t *etcs_packet_to_train_by_nid_packet(uint8_t nid_packet);

const etcs_packet_t *etcs_packet_to_track_unknown(void);

const etcs_packet_t *etcs_packet_to_train_unknown(void);

#endif //ETCS_PACKETS_H
