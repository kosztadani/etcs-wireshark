#ifndef ETCS_COMMON_H
#define ETCS_COMMON_H

#include <stdint.h>

static bool tvb_bits_exist(const tvbuff_t *tvb, const unsigned offset, const unsigned length) {
        const int last_byte = (offset + length - 1) / 8;
        return tvb_offset_exists(tvb, last_byte);
}

typedef struct {
        uint8_t major;
        uint8_t minor;
} etcs_version_t;

static int compare_etcs_version(const etcs_version_t *a, const etcs_version_t *b) {
        if (a->major > b->major) {
                return 1;
        }
        if (a->major < b->major) {
                return -1;
        }
        if (a->minor > b->minor) {
                return 1;
        }
        if (a->minor < b->minor) {
                return -1;
        }
        return 0;
}

static int compare_etcs_version_voids(const void *a, const void *b) {
        return compare_etcs_version(a, b);
}

static etcs_version_t read_etcs_version(tvbuff_t *tvb, const unsigned offset) {
        const uint8_t major = tvb_get_bits8(tvb, offset, 3);
        const uint8_t minor = tvb_get_bits8(tvb, offset + 3, 4);
        return (etcs_version_t){major, minor};
}

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

static void register_var_generic(etcs_variable_t *var, hf_register_info *destination) {
        *destination = (hf_register_info){
                &var->wireshark_hf,
                {
                        var->abbreviation,
                        var->wireshark_abbreviation,
                        FT_UINT64,
                        BASE_DEC,
                        NULL,
                        0x0,
                        NULL,
                        HFILL
                }
        };
}

static void register_var(etcs_variable_t *var, hf_register_info *destination) {
        if (var->register_field == NULL) {
                register_var_generic(var, destination);
                return;
        }
        var->register_field(var, destination);
}

static proto_item *dissect_var_generic(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset) {
        proto_item *item = proto_tree_add_bits_item(
                tree,
                var.wireshark_hf,
                tvb,
                *offset,
                var.size,
                ENC_BIG_ENDIAN
        );
        *offset += var.size;
        return item;
}

static proto_item *dissect_var_ret_generic(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree,
                                           unsigned *offset, uint64_t *return_value) {
        proto_item *item = proto_tree_add_bits_ret_val(
                tree,
                var.wireshark_hf,
                tvb,
                *offset,
                var.size,
                return_value,
                ENC_BIG_ENDIAN
        );
        *offset += var.size;
        return item;
}


static proto_item *dissect_var(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset) {
        if (var.dissect == NULL && var.dissect_ret == NULL) {
                return dissect_var_generic(var, tvb, tree, offset);
        }
        if (var.dissect == NULL) {
                uint64_t dummy;
                return var.dissect_ret(var, tvb, tree, offset, &dummy);
        }
        return var.dissect(var, tvb, tree, offset);
}

static proto_item *dissect_var_ret(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree,
                                   unsigned *offset, uint64_t *return_value) {
        if (var.dissect_ret == NULL) {
                return dissect_var_ret_generic(var, tvb, tree, offset, return_value);
        }
        return var.dissect_ret(var, tvb, tree, offset, return_value);
}

#define DISSECT_VAR(var) dissect_var(VAR(var), tvb, tree, offset)

#define DISSECT_VAR_RET(var, ret) dissect_var_ret(VAR(var), tvb, tree, offset, ret)

#define ETCS_DEFAULT_VERSION ( (etcs_version_t) { 3, 0 } )

#endif //ETCS_COMMON_H
