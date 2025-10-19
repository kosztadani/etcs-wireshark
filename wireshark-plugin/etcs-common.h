#ifndef ETCS_COMMON_H
#define ETCS_COMMON_H

#if (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 4) || WIRESHARK_VERSION_MAJOR >= 5
#include <wsutil/array.h>
#else
#include <epan/packet.h>
#endif

#include <stdint.h>

#define DISSECT_VAR(var) dissect_var(VAR(var), tvb, tree, offset)

#define DISSECT_VAR_RET(var, ret) dissect_var_ret(VAR(var), tvb, tree, offset, ret)

#define ETCS_DEFAULT_VERSION ( (etcs_version_t) { 3, 0 } )

typedef struct {
        uint8_t major;
        uint8_t minor;
} etcs_version_t;

typedef struct etcs_variable_t {
        const char *abbreviation;
        const uint8_t size;
        int wireshark_hf;
        const char *wireshark_abbreviation;

        void (*register_field)(struct etcs_variable_t *self, hf_register_info *destination);

        proto_item * (*dissect)(struct etcs_variable_t self, tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

        proto_item * (*dissect_ret)(struct etcs_variable_t self, tvbuff_t *tvb, proto_tree *tree, unsigned *offset,
                                    uint64_t *ret);
} etcs_variable_t;

typedef struct {
        int l_packet; // -1 if packet doesn't have L_PACKET
} etcs_packet_dissected_t;

typedef struct {
        uint8_t nid_packet;
        const char *name;
        int wireshark_hf;
        int wireshark_ett;
        const char *wireshark_abbreviation;

        etcs_packet_dissected_t (*dissect)(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, etcs_version_t version);
} etcs_packet_t;

typedef enum {
        MESSAGE_TRACK_TO_TRAIN,
        MESSAGE_TRAIN_TO_TRACK,
        MESSAGE_ANY_DIRECTION
} etcs_message_direction_t;

typedef struct {
        uint8_t nid_message;
        const char *name;
        const char *wireshark_name;
        etcs_message_direction_t direction;
        int wireshark_hf;
        const char *wireshark_abbreviation;

        void (*dissect)(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, etcs_version_t version);
} etcs_message_t;

typedef struct {
        etcs_version_t version;
} euroradio_conversation_t;


const char *val_to_str_compat(uint32_t val, const value_string *vs, const char *fmt);

bool tvb_bits_exist(const tvbuff_t *tvb, unsigned offset, unsigned length);

int compare_etcs_version(const etcs_version_t *a, const etcs_version_t *b);

int compare_etcs_version_voids(const void *a, const void *b);

etcs_version_t read_etcs_version(tvbuff_t *tvb, unsigned offset);

proto_item *dissect_var_generic(etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

proto_item *dissect_var_ret_generic(etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset,
                                    uint64_t *return_value);

proto_item *dissect_var(etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

proto_item *dissect_var_ret(etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset,
                            uint64_t *return_value);

#endif //ETCS_COMMON_H
