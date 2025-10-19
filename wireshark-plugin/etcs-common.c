#include "etcs-common.h"

#if (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 6) || WIRESHARK_VERSION_MAJOR > 4
#include <epan/wmem_scopes.h>
#endif

const char *val_to_str_compat(const uint32_t val, const value_string *vs, const char *fmt) {
#if (WIRESHARK_VERSION_MAJOR == 4 && WIRESHARK_VERSION_MINOR >= 6) || WIRESHARK_VERSION_MAJOR > 4
        return val_to_str(wmem_epan_scope(), val, vs, fmt);
#else
        return val_to_str(val, vs, fmt);
#endif
}

bool tvb_bits_exist(const tvbuff_t *tvb, const unsigned offset, const unsigned length) {
        const int last_byte = (offset + length - 1) / 8;
        return tvb_offset_exists(tvb, last_byte);
}

int compare_etcs_version(const etcs_version_t *a, const etcs_version_t *b) {
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

int compare_etcs_version_voids(const void *a, const void *b) {
        return compare_etcs_version(a, b);
}

etcs_version_t read_etcs_version(tvbuff_t *tvb, const unsigned offset) {
        const uint8_t major = tvb_get_bits8(tvb, offset, 3);
        const uint8_t minor = tvb_get_bits8(tvb, offset + 3, 4);
        return (etcs_version_t){major, minor};
}

proto_item *dissect_var_generic(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset) {
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

proto_item *dissect_var_ret_generic(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree,
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

proto_item *dissect_var(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree, unsigned *offset) {
        if (var.dissect == NULL && var.dissect_ret == NULL) {
                return dissect_var_generic(var, tvb, tree, offset);
        }
        if (var.dissect == NULL) {
                uint64_t dummy;
                return var.dissect_ret(var, tvb, tree, offset, &dummy);
        }
        return var.dissect(var, tvb, tree, offset);
}

proto_item *dissect_var_ret(const etcs_variable_t var, tvbuff_t *tvb, proto_tree *tree,
                            unsigned *offset, uint64_t *return_value) {
        if (var.dissect_ret == NULL) {
                return dissect_var_ret_generic(var, tvb, tree, offset, return_value);
        }
        return var.dissect_ret(var, tvb, tree, offset, return_value);
}
