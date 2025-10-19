#ifndef ETCS_MESSAGES_H
#define ETCS_MESSAGES_H

#include "etcs-common.h"

void init_message_info(void);

void etcs_register_messages(int proto);

const etcs_message_t *etcs_message_by_nid(uint8_t nid_message);

const etcs_message_t *etcs_message_unknown(void);

const value_string *etcs_message_names(void);

#endif //ETCS_MESSAGES_H
