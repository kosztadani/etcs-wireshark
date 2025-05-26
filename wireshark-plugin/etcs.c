#include <ws_version.h>

#if WIRESHARK_VERSION_MAJOR != 4 || WIRESHARK_VERSION_MINOR != 4
#warning "Only tested with Wireshark version 4.4"
#endif

#define WS_BUILD_DLL

#include <wsutil/plugins.h>
#include <epan/packet.h>

#include "etcs.h"

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

static int proto_etcs;

static dissector_handle_t handle_etcs;

static int ett_etcs;

static void proto_register_etcs(void);

static void proto_register_handoff_etcs(void);

static int dissect_etcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

void plugin_register(void) {
        static proto_plugin plug;
        plug.register_protoinfo = proto_register_etcs;
        plug.register_handoff = proto_register_handoff_etcs;
        proto_register_plugin(&plug);
}

uint32_t plugin_describe(void) {
        return WS_PLUGIN_DESC_DISSECTOR;
}

static void proto_register_etcs(void) {
        static hf_register_info hf[] = {
        };
        static int *ett[] = {
                &ett_etcs
        };
        proto_etcs = proto_register_protocol("European Train Control System", "ETCS", "etcs");
        proto_register_field_array(proto_etcs, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

static void proto_register_handoff_etcs(void) {
        handle_etcs = create_dissector_handle(dissect_etcs, proto_etcs);
        dissector_add_for_decode_as("udp.port", handle_etcs);
}

static int dissect_etcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, _U_ void *data) {
        proto_tree_add_item(tree, proto_etcs, tvb, 0, tvb_reported_length(tvb), ENC_NA);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETCS");
        return tvb_reported_length(tvb);
}