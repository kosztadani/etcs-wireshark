#include <ws_version.h>

#if WIRESHARK_VERSION_MAJOR != 4 || WIRESHARK_VERSION_MINOR != 4
#warning "Only tested with Wireshark version 4.4"
#endif

#define WS_BUILD_DLL

#include <wsutil/plugins.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <inttypes.h>

#include "etcs.h"

#include "etcs-common.h"

#include "etcs-vars.c"
#include "etcs-packets.c"
#include "etcs-messages.c"

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

static int proto_etcs;

static int proto_etcs_balise;

static int proto_etcs_loop;

static int proto_etcs_radio;

static int ett_etcs_balise;

static int ett_etcs_loop;

static int ett_etcs_radio;

static int ett_etcs_radio_message;

static int hf_etcs_version;

static expert_field ei_unknown_version;

static expert_field ei_inconsistent_l_packet;

static expert_field ei_unknown_message;

static expert_field ei_unknown_packet;

static void proto_register_etcs(void);

static void register_fields_and_subtrees(void);

static void register_experts(void);

static void proto_reg_handoff_etcs(void);

static int dissect_etcs_balise(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static int dissect_etcs_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static int dissect_etcs_radio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static etcs_version_t initialize_etcs_conversation_from_message_155(const packet_info *pinfo);

static etcs_version_t initialize_etcs_conversation_from_message_32(tvbuff_t *tvb, const packet_info *pinfo);

static etcs_version_t initialize_etcs_conversation_from_message_159(tvbuff_t *tvb, const packet_info *pinfo);

static void store_etcs_version_in_new_conversation(const packet_info *pinfo, etcs_version_t version);

static etcs_version_t *get_etcs_version_from_conversation(const packet_info *pinfo);

static conversation_element_t *dummy_conversation_elements();

static etcs_version_t get_etcs_version(tvbuff_t *tvb, const packet_info *pinfo, uint8_t nid_message);

static void add_protocol_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, etcs_version_t version);

static bool is_version_supported(etcs_version_t version);

static void register_packet(etcs_packet_t *pack, hf_register_info *destination);

static void register_message(etcs_message_t *message, hf_register_info *destination);

static wmem_list_t *dissect_packets(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree, unsigned *offset,
                                    etcs_message_direction_t direction, etcs_version_t version);

static etcs_packet_t *get_packet(uint8_t nid_packet, etcs_message_direction_t direction);

static void append_packet_list(const wmem_list_t *packet_ids, const packet_info *pinfo);

void plugin_register(void) {
        static proto_plugin plug;
        init_packet_info();
        init_message_info();
        plug.register_protoinfo = proto_register_etcs;
        plug.register_handoff = proto_reg_handoff_etcs;
        proto_register_plugin(&plug);
}

uint32_t plugin_describe(void) {
        return WS_PLUGIN_DESC_DISSECTOR;
}

static const value_string m_dup_values[] = {
        {0b00, "no duplicates"},
        {0b01, "duplicate of next"},
        {0b10, "duplicate of previous"},
        {0, NULL}
};

static void proto_register_etcs(void) {
        register_fields_and_subtrees();
        register_experts();
}

static void register_fields_and_subtrees(void) {
        static hf_register_info hf[4
                                   + array_length(etcs_variables)
                                   + array_length(etcs_packets_to_train_raw)
                                   + array_length(etcs_packets_to_track_raw)
                                   + array_length(etcs_messages_raw)
        ];
        static int *ett[6
                        + array_length(etcs_packets_to_train_raw)
                        + array_length(etcs_packets_to_track_raw)
        ];
        int hf_index = 0;
        int ett_index = 0;
        register_packet(&etcs_unknown_packet_to_train, &hf[hf_index++]);
        register_packet(&etcs_unknown_packet_to_track, &hf[hf_index++]);
        register_message(&etcs_unknown_message, &hf[hf_index++]);
        hf[hf_index++] = (hf_register_info){
                &hf_etcs_version,
                {
                        "ETCS version used for dissection",
                        "etcs.version",
                        FT_STRING,
                        BASE_NONE,
                        NULL,
                        0x0,
                        NULL,
                        HFILL
                }
        };
        ett[ett_index++] = &ett_etcs_balise;
        ett[ett_index++] = &ett_etcs_loop;
        ett[ett_index++] = &ett_etcs_radio;
        ett[ett_index++] = &ett_etcs_radio_message;
        ett[ett_index++] = &etcs_unknown_packet_to_train.wireshark_ett;
        ett[ett_index++] = &etcs_unknown_packet_to_track.wireshark_ett;
        for (size_t i = 0; i < array_length(etcs_variables); i++) {
                etcs_variable_t *var = &etcs_variables[i];
                register_var(var, &hf[hf_index++]);
        }
        for (size_t i = 0; i < array_length(etcs_packets_to_train_raw); i++) {
                etcs_packet_t *pack = &etcs_packets_to_train_raw[i];
                register_packet(pack, &hf[hf_index++]);
                ett[ett_index++] = &pack->wireshark_ett;
        }
        for (size_t i = 0; i < array_length(etcs_packets_to_track_raw); i++) {
                etcs_packet_t *pack = &etcs_packets_to_track_raw[i];
                register_packet(pack, &hf[hf_index++]);
                ett[ett_index++] = &pack->wireshark_ett;
        }
        for (size_t i = 0; i < array_length(etcs_messages_raw); i++) {
                etcs_message_t *message = &etcs_messages_raw[i];
                register_message(message, &hf[hf_index++]);
        }
        proto_etcs = proto_register_protocol(
                "European Train Control System",
                "ETCS",
                "etcs"
        );
        proto_register_field_array(proto_etcs, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
        proto_etcs_balise = proto_register_protocol(
                "European Train Control System: Eurobalise",
                "ETCS-BALISE",
                "etcs.balise"
        );
        proto_etcs_loop = proto_register_protocol(
                "European Train Control System: Euroloop",
                "ETCS-LOOP",
                "etcs.loop"
        );
        proto_etcs_radio = proto_register_protocol(
                "European Train Control System: Euroradio",
                "ETCS-RADIO",
                "etcs.radio"
        );
}

static void register_packet(etcs_packet_t *pack, hf_register_info *destination) {
        *destination = (hf_register_info){
                &pack->wireshark_hf, {
                        pack->name,
                        pack->wireshark_abbreviation,
                        FT_NONE,
                        BASE_NONE,
                        NULL,
                        0x0,
                        NULL,
                        HFILL
                }
        };
}

static void register_message(etcs_message_t *message, hf_register_info *destination) {
        *destination = (hf_register_info){
                &message->wireshark_hf, {
                        message->wireshark_name,
                        message->wireshark_abbreviation,
                        FT_NONE,
                        BASE_NONE,
                        NULL,
                        0x0,
                        NULL,
                        HFILL
                }
        };
}

static void register_experts(void) {
        static ei_register_info ei[] = {
                {
                        &ei_unknown_version,
                        {
                                "etcs.experts.unknown_version",
                                PI_PROTOCOL,
                                PI_WARN,
                                "Unknown ETCS version",
                                EXPFILL
                        }
                },
                {
                        &ei_inconsistent_l_packet,
                        {
                                "etcs.experts.inconsistent_l_packet",
                                PI_MALFORMED,
                                PI_ERROR,
                                "L_PACKET is inconsistent with decoded packet",
                                EXPFILL
                        }
                },
                {
                        &ei_unknown_message,
                        {
                                "etcs.experts.unknown_message",
                                PI_UNDECODED,
                                PI_WARN,
                                "Unknown message",
                                EXPFILL
                        }
                },
                {
                        &ei_unknown_packet,
                        {
                                "etcs.experts.unknown_packet",
                                PI_UNDECODED,
                                PI_WARN,
                                "Unknown packet",
                                EXPFILL
                        }
                }
        };
        expert_module_t *module = expert_register_protocol(proto_etcs);
        expert_register_field_array(module, ei, array_length(ei));;
}

static void proto_reg_handoff_etcs(void) {
        static dissector_handle_t handle_etcs_balise;
        static dissector_handle_t handle_etcs_loop;
        static dissector_handle_t handle_etcs_radio;
        handle_etcs_balise = register_dissector(
                "ETCS-BALISE",
                dissect_etcs_balise,
                proto_etcs_balise
        );
        handle_etcs_loop = register_dissector(
                "ETCS-LOOP",
                dissect_etcs_loop,
                proto_etcs_loop
        );
        handle_etcs_radio = register_dissector(
                "ETCS-RADIO",
                dissect_etcs_radio,
                proto_etcs_radio
        );
        dissector_add_for_decode_as("udp.port", handle_etcs_balise);
        dissector_add_for_decode_as("udp.port", handle_etcs_loop);
        dissector_add_for_decode_as("udp.port", handle_etcs_radio);
}

static int dissect_etcs_balise(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, _U_ void *data) {
        proto_item *etcs = proto_tree_add_item(tree, proto_etcs, tvb, 0, (int) tvb_reported_length(tvb), ENC_NA);
        proto_item_set_hidden(etcs);
        proto_item *ti = proto_tree_add_item(tree, proto_etcs_balise, tvb, 0, (int) tvb_reported_length(tvb), ENC_NA);
        proto_tree *sub = proto_item_add_subtree(ti, ett_etcs_balise);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETCS");
        unsigned offset = 0;
        uint64_t n_pig; // position in group (starts at 0)
        uint64_t n_total; // total in group, minus 1
        uint64_t nid_bg; // identifier of group
        uint64_t m_dup; // information about duplication
        const etcs_version_t etcs_version = read_etcs_version(tvb, offset + 1);
        add_protocol_version(tvb, pinfo, sub, etcs_version);
        dissect_var(VAR(Q_UPDOWN), tvb, sub, &offset);
        dissect_var(VAR(M_VERSION), tvb, sub, &offset);
        dissect_var(VAR(Q_MEDIA), tvb, sub, &offset);
        dissect_var_ret(VAR(N_PIG), tvb, sub, &offset, &n_pig);
        dissect_var_ret(VAR(N_TOTAL), tvb, sub, &offset, &n_total);
        dissect_var_ret(VAR(M_DUP), tvb, sub, &offset, &m_dup);
        dissect_var(VAR(M_MCOUNT), tvb, sub, &offset);
        dissect_var(VAR(NID_C), tvb, sub, &offset);
        dissect_var_ret(VAR(NID_BG), tvb, sub, &offset, &nid_bg);
        dissect_var(VAR(Q_LINK), tvb, sub, &offset);
        col_add_fstr(
                pinfo->cinfo,
                COL_INFO,
                "Eurobalise (id %" PRIu64 ", position %" PRIu64 " out of %" PRIu64 ", %s): ",
                nid_bg,
                n_pig + 1,
                n_total + 1,
                val_to_str(m_dup, m_dup_values, "unknown M_DUP")
        );
        wmem_list_t *packet_ids = dissect_packets(tvb, pinfo, ti, &offset, MESSAGE_TRACK_TO_TRAIN, etcs_version);
        append_packet_list(packet_ids, pinfo);
        wmem_destroy_list(packet_ids);
        return (int) tvb_reported_length(tvb);
}

static int dissect_etcs_loop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, _U_ void *data) {
        proto_item *etcs = proto_tree_add_item(tree, proto_etcs, tvb, 0, (int) tvb_reported_length(tvb), ENC_NA);
        proto_item_set_hidden(etcs);
        proto_item *ti = proto_tree_add_item(tree, proto_etcs_loop, tvb, 0, (int) tvb_reported_length(tvb), ENC_NA);
        proto_tree *sub = proto_item_add_subtree(ti, ett_etcs_loop);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETCS");
        unsigned offset = 0;
        uint64_t nid_loop; // identity of loop
        const etcs_version_t etcs_version = read_etcs_version(tvb, offset + 1);
        add_protocol_version(tvb, pinfo, sub, etcs_version);
        dissect_var(VAR(Q_UPDOWN), tvb, sub, &offset);
        dissect_var(VAR(M_VERSION), tvb, sub, &offset);
        dissect_var(VAR(Q_MEDIA), tvb, sub, &offset);
        dissect_var(VAR(NID_C), tvb, sub, &offset);
        dissect_var_ret(VAR(NID_LOOP), tvb, sub, &offset, &nid_loop);
        col_add_fstr(
                pinfo->cinfo,
                COL_INFO,
                "Euroloop (id %" PRIu64 "): ",
                nid_loop
        );
        wmem_list_t *packet_ids = dissect_packets(tvb, pinfo, ti, &offset, MESSAGE_TRACK_TO_TRAIN, etcs_version);
        append_packet_list(packet_ids, pinfo);
        wmem_destroy_list(packet_ids);
        return (int) tvb_reported_length(tvb);
}

static int dissect_etcs_radio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, _U_ void *data) {
        proto_item *etcs = proto_tree_add_item(tree, proto_etcs, tvb, 0, (int) tvb_reported_length(tvb), ENC_NA);
        proto_item_set_hidden(etcs);
        proto_item *ti = proto_tree_add_item(tree, proto_etcs_radio, tvb, 0, (int) tvb_reported_length(tvb), ENC_NA);
        proto_tree *sub = proto_item_add_subtree(ti, ett_etcs_radio);
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETCS");
        unsigned offset = 0;
        const uint8_t nid_message = tvb_get_bits8(tvb, offset, VAR(NID_MESSAGE).size);
        col_add_fstr(
                pinfo->cinfo,
                COL_INFO,
                "Euroradio: message %" PRIu8 " (%s)",
                nid_message,
                val_to_str(nid_message, etcs_nid_message_values, "unknown")
        );
        const int byte_offset_start = (int) offset / 8;
        const etcs_version_t etcs_version = get_etcs_version(tvb, pinfo, nid_message);
        add_protocol_version(tvb, pinfo, sub, etcs_version);
        const etcs_message_t *message = etcs_messages[nid_message];
        if (message == NULL) {
                message = &etcs_unknown_message;
        }
        proto_item *message_item = proto_tree_add_item(
                sub,
                message->wireshark_hf,
                tvb,
                byte_offset_start,
                -1,
                ENC_NA
        );
        if (message == &etcs_unknown_message) {
                expert_add_info_format(
                        pinfo,
                        message_item,
                        &ei_unknown_message,
                        "Unknown message (%" PRIu8 ")",
                        nid_message
                );
        }
        proto_tree *message_tree = proto_item_add_subtree(message_item, ett_etcs_radio_message);
        if (message->dissect != NULL) {
                col_append_str(pinfo->cinfo, COL_INFO, ", ");
                message->dissect(tvb, message_tree, &offset, etcs_version);
                wmem_list_t *packet_ids = dissect_packets(
                        tvb,
                        pinfo,
                        ti,
                        &offset,
                        message->direction,
                        etcs_version
                );
                append_packet_list(packet_ids, pinfo);
                wmem_destroy_list(packet_ids);
        }
        const int byte_offset_end = ((int) offset - 1) / 8;
        proto_item_set_len(message_item, byte_offset_end - byte_offset_start + 1);
        return (int) tvb_reported_length(tvb);
}

static etcs_version_t get_etcs_version(tvbuff_t *tvb, const packet_info *pinfo, const uint8_t nid_message) {
        if (nid_message == 155) {
                return initialize_etcs_conversation_from_message_155(pinfo);
        }
        if (nid_message == 32) {
                return initialize_etcs_conversation_from_message_32(tvb, pinfo);
        }
        if (nid_message == 159) {
                return initialize_etcs_conversation_from_message_159(tvb, pinfo);
        }
        const etcs_version_t *ptr = get_etcs_version_from_conversation(pinfo);
        if (ptr) {
                return *ptr;
        }
        return ETCS_DEFAULT_VERSION;
}

static etcs_version_t initialize_etcs_conversation_from_message_155(const packet_info *pinfo) {
        const etcs_version_t version = ETCS_DEFAULT_VERSION;
        if (!PINFO_FD_VISITED(pinfo)) {
                store_etcs_version_in_new_conversation(pinfo, version);
        }
        return version;
}

static etcs_version_t initialize_etcs_conversation_from_message_32(tvbuff_t *tvb, const packet_info *pinfo) {
        const unsigned offset = VAR(NID_MESSAGE).size
                                + VAR(L_MESSAGE).size
                                + VAR(T_TRAIN).size
                                + VAR(M_ACK).size
                                + VAR(NID_LRBG).size;
        if (!tvb_bits_exist(tvb, offset, VAR(M_VERSION).size)) {
                return ETCS_DEFAULT_VERSION;
        }
        const etcs_version_t version = read_etcs_version(tvb, offset);
        if (!PINFO_FD_VISITED(pinfo)) {
                store_etcs_version_in_new_conversation(pinfo, version);
        }
        return version;
}

static etcs_version_t initialize_etcs_conversation_from_message_159(tvbuff_t *tvb, const packet_info *pinfo) {
        etcs_version_t *rbc_version = get_etcs_version_from_conversation(pinfo);
        if (!rbc_version) {
                return ETCS_DEFAULT_VERSION;
        }
        unsigned offset = VAR(NID_MESSAGE).size
                          + VAR(L_MESSAGE).size
                          + VAR(T_TRAIN).size
                          + VAR(NID_ENGINE).size;

        if (!tvb_bits_exist(tvb, offset, VAR(NID_PACKET).size + VAR(L_PACKET).size)) {
                return *rbc_version;
        }
        const uint8_t nid_packet = tvb_get_bits8(tvb, offset, VAR(NID_PACKET).size);
        if (nid_packet != 2) {
                return *rbc_version;
        }
        offset += VAR(NID_PACKET).size + VAR(L_PACKET).size;
        etcs_version_t supported_versions[32]; // 32 = 1 + maximum of N_ITER
        if (!tvb_bits_exist(tvb, offset, VAR(M_VERSION).size + VAR(N_ITER).size)) {
                return *rbc_version;
        }
        supported_versions[0] = read_etcs_version(tvb, offset);
        offset += VAR(M_VERSION).size;
        const uint8_t n_iter = tvb_get_bits8(tvb, offset, VAR(N_ITER).size);
        offset += VAR(N_ITER).size;;
        if (!tvb_bits_exist(tvb, offset, n_iter * VAR(M_VERSION).size)) {
                return *rbc_version;
        }
        for (int i = 0; i < n_iter; i++) {
                supported_versions[i + 1] = read_etcs_version(tvb, offset);
                offset += VAR(M_VERSION).size;
        }
        qsort(supported_versions, n_iter + 1, sizeof(etcs_version_t), compare_etcs_version_voids);
        const etcs_version_t *version = NULL;
        for (int i = 0; i < n_iter + 1; i++) {
                const int comparison = compare_etcs_version(rbc_version, &supported_versions[i]);
                if (comparison == 0) {
                        version = &supported_versions[i];
                        break;
                }
                if (comparison > 0) {
                        version = &supported_versions[i];
                }
                if (comparison < 0) {
                        break;
                }
        }
        if (version == NULL) {
                version = rbc_version;
        }
        if (!PINFO_FD_VISITED(pinfo)) {
                store_etcs_version_in_new_conversation(pinfo, *version);
        }
        return *version;
}

static void store_etcs_version_in_new_conversation(const packet_info *pinfo, const etcs_version_t version) {
        conversation_t *conversation = conversation_new_full(pinfo->num, dummy_conversation_elements());
        euroradio_conversation_t *euroradio_conversation = wmem_alloc(
                wmem_file_scope(),
                sizeof(euroradio_conversation_t)
        );
        euroradio_conversation->version = version;
        conversation_add_proto_data(conversation, proto_etcs_radio, euroradio_conversation);
}

static etcs_version_t *get_etcs_version_from_conversation(const packet_info *pinfo) {
        const conversation_t *conversation = find_conversation_full(pinfo->num, dummy_conversation_elements());
        if (conversation) {
                euroradio_conversation_t *euroradio_conversation = conversation_get_proto_data(
                        conversation,
                        proto_etcs_radio
                );
                if (euroradio_conversation) {
                        return &euroradio_conversation->version;
                }
        }
        return NULL;
}

static conversation_element_t *dummy_conversation_elements(void) {
        static conversation_element_t elements[2] = {
                {
                        .type = CE_UINT,
                        .uint_val = 0,
                },
                {
                        .type = CE_CONVERSATION_TYPE,
                        .conversation_type_val = CONVERSATION_NONE
                }
        };
        return elements;
}

static void add_protocol_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const etcs_version_t version) {
        wmem_strbuf_t *version_string = wmem_strbuf_new(pinfo->pool, "");
        wmem_strbuf_append_printf(version_string, "%" PRIu8 ".%" PRIu8, version.major, version.minor);
        proto_item *item = proto_tree_add_string(
                tree,
                hf_etcs_version,
                tvb,
                0,
                0,
                version_string->str
        );
        proto_item_set_generated(item);
        if (!is_version_supported(version)) {
                expert_add_info(pinfo, item, &ei_unknown_version);
        }
}

static bool is_version_supported(const etcs_version_t version) {
        static etcs_version_t supported_versions[] = {
                {1, 0},
                {1, 1},
                {2, 0},
                {2, 1},
                {2, 2},
                {2, 3},
                {3, 0},
        };
        for (size_t i = 0; i < array_length(supported_versions); i++) {
                if (compare_etcs_version(&version, &supported_versions[i]) == 0) {
                        return true;
                }
        }
        return false;
}

static wmem_list_t *dissect_packets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset,
                                    const etcs_message_direction_t direction, const etcs_version_t version) {
        wmem_list_t *packet_ids = wmem_list_new(pinfo->pool);
        uint8_t nid_packet;
        do {
                const int byte_offset_start = (int) *offset / 8;
                if (!tvb_bits_exist(tvb, *offset, VAR(NID_PACKET).size)) {
                        break;
                }
                nid_packet = tvb_get_bits8(tvb, *offset, VAR(NID_PACKET).size);
                wmem_list_append(packet_ids, wmem_memdup(pinfo->pool, &nid_packet, sizeof(uint8_t)));
                const etcs_packet_t *packet = get_packet(nid_packet, direction);
                if (!packet) {
                        break;
                }
                proto_item *packet_item = proto_tree_add_item(
                        tree,
                        packet->wireshark_hf,
                        tvb,
                        byte_offset_start,
                        -1,
                        ENC_NA
                );
                proto_tree *packet_tree = proto_item_add_subtree(packet_item, packet->wireshark_ett);
                if (packet == &etcs_unknown_packet_to_track || packet == &etcs_unknown_packet_to_train) {
                        expert_add_info_format(
                                pinfo,
                                packet_item,
                                &ei_unknown_packet,
                                "Unknown packet (%" PRIu8 ")",
                                nid_packet
                        );
                }
                if (packet->dissect == NULL) {
                        dissect_var(VAR(NID_PACKET), tvb, packet_tree, offset);
                        break;
                }
                const unsigned initial_offset = *offset;
                const etcs_packet_dissected_t dissected = packet->dissect(tvb, packet_tree, offset, version);
                const int length = (int) (*offset - initial_offset);
                if (dissected.l_packet != -1 && length != dissected.l_packet) {
                        expert_add_info_format(
                                pinfo,
                                packet_item,
                                &ei_inconsistent_l_packet,
                                "L_PACKET (%i) is inconsistent with processed length (%i)",
                                dissected.l_packet,
                                length
                        );
                }
                const int byte_offset_end = ((int) *offset - 1) / 8;
                proto_item_set_len(packet_item, byte_offset_end - byte_offset_start + 1);
        } while (nid_packet != 255);
        return packet_ids;
}

static etcs_packet_t *get_packet(const uint8_t nid_packet, const etcs_message_direction_t direction) {
        etcs_packet_t *result = NULL;
        switch (direction) {
                case MESSAGE_TRACK_TO_TRAIN:
                        result = etcs_packets_to_train[nid_packet];
                        if (result == NULL) {
                                result = &etcs_unknown_packet_to_train;
                        }
                        break;
                case MESSAGE_TRAIN_TO_TRACK:
                        result = etcs_packets_to_track[nid_packet];
                        if (result == NULL) {
                                result = &etcs_unknown_packet_to_track;
                        }
                        break;
                case MESSAGE_ANY_DIRECTION:
                        // this shouldn't happen
                        break;
        }
        return result;
}

static void append_packet_list(const wmem_list_t *packet_ids, const packet_info *pinfo) {
        const unsigned count = wmem_list_count(packet_ids);
        const wmem_list_frame_t *next_frame = wmem_list_head(packet_ids);
        if (count == 0) {
                col_append_str(pinfo->cinfo, COL_INFO, "no packets");
        } else if (count == 1) {
                const uint8_t *nid_packet = wmem_list_frame_data(next_frame);
                col_append_fstr(pinfo->cinfo, COL_INFO, "packet %" PRIu8, *nid_packet);
        } else {
                col_append_str(pinfo->cinfo, COL_INFO, "packets ");
                bool first = true;
                do {
                        const uint8_t *nid_packet = wmem_list_frame_data(next_frame);
                        if (first) {
                                col_append_fstr(pinfo->cinfo, COL_INFO, "%" PRIu8, *nid_packet);
                        } else {
                                col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%" PRIu8, *nid_packet);
                        }
                        next_frame = wmem_list_frame_next(next_frame);
                        first = false;
                } while (next_frame != NULL);
        }
}
