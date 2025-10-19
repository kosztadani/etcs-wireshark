#include "etcs-vars.h"

#include "etcs-common.h"

#define DEF_VAR(name, size) { name , ( size ), 0, "etcs.var." name, NULL, NULL, NULL }

#define DEF_VAR_CUSTOM(name, size, registrator, dissect, dissect_ret) { name , ( size ), 0, "etcs.var." name, registrator, dissect, dissect_ret }

static void register_var_generic(etcs_variable_t *var, hf_register_info *destination);

static void register_var(etcs_variable_t *var, hf_register_info *destination);

static proto_item *dissect_var_ret_x_text(const etcs_variable_t self, tvbuff_t *tvb, proto_tree *tree, unsigned *offset,
                                          uint64_t *return_value) {
        proto_item *item = proto_tree_add_bits_ret_val(
                tree,
                self.wireshark_hf,
                tvb,
                *offset,
                self.size,
                return_value,
                ENC_BIG_ENDIAN
        );
        *offset += self.size;
        const uint64_t value = *return_value;
        const char c = (char) value;
        // display printable ASCII characters; pad so that it lines up after decimal value
        if (value >= ' ' && value <= 99) {
                proto_item_append_text(item, "  ['%c']", c);
        } else if (value >= 100 && value <= '~') {
                proto_item_append_text(item, " ['%c']", c);
        }
        return item;
}

static proto_item *dissect_var_ret_m_version(const etcs_variable_t self, tvbuff_t *tvb, proto_tree *tree,
                                             unsigned *offset, uint64_t *return_value) {
        proto_item *item = proto_tree_add_bits_ret_val(
                tree,
                self.wireshark_hf,
                tvb,
                *offset,
                self.size,
                return_value,
                ENC_BIG_ENDIAN
        );
        const etcs_version_t version = read_etcs_version(tvb, *offset);
        *offset += self.size;
        proto_item_append_text(item, " [\"%" PRIu8 ".%" PRIu8 "\"]", version.major, version.minor);
        return item;
}

/**
 * This must be kept in sync with the enumeration in etcs-vars.h.
 */
static etcs_variable_t etcs_variables[] = {
        DEF_VAR("A_NVMAXREDADH1", 6),
        DEF_VAR("A_NVMAXREDADH2", 6),
        DEF_VAR("A_NVMAXREDADH3", 6),
        DEF_VAR("A_NVP12", 6),
        DEF_VAR("A_NVP23", 6),
        DEF_VAR("D_ADHESION", 15),
        DEF_VAR("D_AXLELOAD", 15),
        DEF_VAR("D_CURRENT", 15),
        DEF_VAR("D_CYCLOC", 15),
        DEF_VAR("D_DP", 15),
        DEF_VAR("D_EMERGENCYSTOP", 15),
        DEF_VAR("D_ENDTIMERSTARTLOC", 15),
        DEF_VAR("D_GRADIENT", 15),
        DEF_VAR("D_INFILL", 15),
        DEF_VAR("D_LEVELTR", 15),
        DEF_VAR("D_LINK", 15),
        DEF_VAR("D_LOC", 15),
        DEF_VAR("D_LOOP", 15),
        DEF_VAR("D_LRBG", 15),
        DEF_VAR("D_LX", 15),
        DEF_VAR("D_MAMODE", 15),
        DEF_VAR("D_NVOVTRP", 15),
        DEF_VAR("D_NVPOTRP", 15),
        DEF_VAR("D_NVROLL", 15),
        DEF_VAR("D_NVSTFF", 15),
        DEF_VAR("D_OL", 15),
        DEF_VAR("D_PBD", 15),
        DEF_VAR("D_PBDSR", 15),
        DEF_VAR("D_POSOFF", 15),
        DEF_VAR("D_RBCTR", 15),
        DEF_VAR("D_REF", 16),
        DEF_VAR("D_REVERSE", 15),
        DEF_VAR("D_SECTIONTIMERSTOPLOC", 15),
        DEF_VAR("D_SR", 15),
        DEF_VAR("D_STARTOL", 15),
        DEF_VAR("D_STARTREVERSE", 15),
        DEF_VAR("D_STATIC", 15),
        DEF_VAR("D_SUITABILITY", 15),
        DEF_VAR("D_TAFDISPLAY", 15),
        DEF_VAR("D_TEXTDISPLAY", 15),
        DEF_VAR("D_TRACKINIT", 15),
        DEF_VAR("D_TRACKCOND", 15),
        DEF_VAR("D_TRACTION", 15),
        DEF_VAR("D_TSR", 15),
        DEF_VAR("D_VALIDNV", 15),
        DEF_VAR("G_A", 8),
        DEF_VAR("G_PBDSR", 8),
        DEF_VAR("G_TSR", 8),
        DEF_VAR("L_ACKLEVELTR", 15),
        DEF_VAR("L_ACKMAMODE", 15),
        DEF_VAR("L_ADHESION", 15),
        DEF_VAR("L_AXLELOAD", 15),
        DEF_VAR("L_CONSISTFRONTENGINEMAX", 15),
        DEF_VAR("L_CONSISTFRONTENGINEMIN", 12),
        DEF_VAR("L_CONSISTFRONTENGINENOM", 12),
        DEF_VAR("L_CONSISTREARENGINEMAX", 12),
        DEF_VAR("L_CONSISTREARENGINEMIN", 12),
        DEF_VAR("L_CONSISTREARENGINENOM", 12),
        DEF_VAR("L_DOUBTOVER", 15),
        DEF_VAR("L_DOUBTUNDER", 15),
        DEF_VAR("L_ENDSECTION", 15),
        DEF_VAR("L_LOOP", 15),
        DEF_VAR("L_LX", 15),
        DEF_VAR("L_MAMODE", 15),
        DEF_VAR("L_MESSAGE", 10),
        DEF_VAR("L_NVKRINT", 5),
        DEF_VAR("L_PACKET", 13),
        DEF_VAR("L_PBDSR", 15),
        DEF_VAR("L_REVERSEAREA", 15),
        DEF_VAR("L_SECTION", 15),
        DEF_VAR("L_STOPLX", 15),
        DEF_VAR("L_TAFDISPLAY", 15),
        DEF_VAR("L_TEXT", 8),
        DEF_VAR("L_TEXTDISPLAY", 15),
        DEF_VAR("L_TRACKCOND", 15),
        DEF_VAR("L_TRAIN", 12),
        DEF_VAR("L_TRAININT", 15),
        DEF_VAR("L_TSR", 15),
        DEF_VAR("M_ACK", 1),
        DEF_VAR("M_ADHESION", 1),
        DEF_VAR("M_AIRTIGHT", 2),
        DEF_VAR("M_AXLELOADCAT", 7),
        DEF_VAR("M_CURRENT", 10),
        DEF_VAR("M_DUP", 2),
        DEF_VAR("M_ERROR", 8),
        DEF_VAR("M_LEVEL", 3),
        DEF_VAR("M_LEVELTEXTDISPLAY", 3),
        DEF_VAR("M_LEVELTR", 3),
        DEF_VAR("M_LINEGAUGE", 8),
        DEF_VAR("M_LINEAXLELOADCAT", 16),
        DEF_VAR("M_LOADINGGAUGE", 8),
        DEF_VAR("M_LOC", 3),
        DEF_VAR("M_MAMODE", 2),
        DEF_VAR("M_MCOUNT", 8),
        DEF_VAR("M_MODE", 5),
        DEF_VAR("M_MODE", 4), // v1 + v2
        DEF_VAR("M_MODETEXTDISPLAY", 4),
        DEF_VAR("M_NVAVADH", 5),
        DEF_VAR("M_NVCONTACT", 2),
        DEF_VAR("M_NVDERUN", 1),
        DEF_VAR("M_NVEBCL", 4),
        DEF_VAR("M_NVKRINT", 5),
        DEF_VAR("M_NVKTINT", 5),
        DEF_VAR("M_NVKVINT", 7),
        DEF_VAR("M_PLATFORM", 4),
        DEF_VAR("M_POSITION", 24),
        DEF_VAR("M_POSITION", 20), // v1
        DEF_VAR("M_TRACKCOND", 4),
        DEF_VAR("M_VOLTAGE", 4),
        DEF_VAR_CUSTOM("M_VERSION", 7, NULL, NULL, dissect_var_ret_m_version),
        DEF_VAR("N_AXLE", 10),
        DEF_VAR("N_ITER", 5),
        DEF_VAR("N_PIG", 3),
        DEF_VAR("N_TOTAL", 3),
        DEF_VAR("NC_CDDIFF", 4),
        DEF_VAR("NC_CDTRAIN", 4),
        DEF_VAR("NC_DIFF", 4),
        DEF_VAR("NC_TRAIN", 15),
        DEF_VAR("NID_BG", 14),
        DEF_VAR("NID_C", 10),
        DEF_VAR("NID_CTRACTION", 10),
        DEF_VAR("NID_EM", 4),
        DEF_VAR("NID_ENGINE", 24),
        DEF_VAR("NID_LOOP", 14),
        DEF_VAR("NID_LRBG", 24),
        DEF_VAR("NID_LTRBG", 24),
        DEF_VAR("NID_LX", 8),
        DEF_VAR("NID_MESSAGE", 8),
        DEF_VAR("NID_MN", 24),
        DEF_VAR("NID_OPERATIONAL", 32),
        DEF_VAR("NID_PACKET", 8),
        DEF_VAR("NID_PRVLRBG", 24),
        DEF_VAR("NID_RADIO", 64),
        DEF_VAR("NID_RBC", 14),
        DEF_VAR("NID_RIU", 14),
        DEF_VAR("NID_NTC", 8),
        DEF_VAR("NID_TEXTMESSAGE", 8),
        DEF_VAR("NID_TSR", 8),
        DEF_VAR("NID_VBCMK", 6),
        DEF_VAR("NID_XUSER", 9),
        DEF_VAR("Q_ASPECT", 1),
        DEF_VAR("Q_CONFTEXTDISPLAY", 1),
        DEF_VAR("Q_DANGERPOINT", 1),
        DEF_VAR("Q_DIFF", 2),
        DEF_VAR("Q_DESK", 1),
        DEF_VAR("Q_DIR", 2),
        DEF_VAR("Q_DIRLRBG", 2),
        DEF_VAR("Q_DIRTRAIN", 2),
        DEF_VAR("Q_DLRBG", 2),
        DEF_VAR("Q_EMERGENCYSTOP", 2),
        DEF_VAR("Q_ENDTIMER", 1),
        DEF_VAR("Q_FRONT", 1),
        DEF_VAR("Q_GDIR", 1),
        DEF_VAR("Q_INFILL", 1),
        DEF_VAR("Q_INTEGRITY", 2),
        DEF_VAR("Q_SAFECONSISTLENGTH", 1),
        DEF_VAR("Q_LGTLOC", 1),
        DEF_VAR("Q_LINK", 1),
        DEF_VAR("Q_LOCACC", 6),
        DEF_VAR("Q_LINKORIENTATION", 1),
        DEF_VAR("Q_LINKREACTION", 2),
        DEF_VAR("Q_LOOPDIR", 1),
        DEF_VAR("Q_LSSMA", 1),
        DEF_VAR("Q_LXSTATUS", 1),
        DEF_VAR("Q_MAMODE", 1),
        DEF_VAR("Q_MARQSTREASON", 5),
        DEF_VAR("Q_MEDIA", 1),
        DEF_VAR("Q_MPOSITION", 1),
        DEF_VAR("Q_NETWORKTYPE", 2),
        DEF_VAR("Q_NEWCOUNTRY", 1),
        DEF_VAR("Q_NVDRIVER_ADHES", 1),
        DEF_VAR("Q_NVEMRRLS", 1),
        DEF_VAR("Q_NVGUIPERM", 1),
        DEF_VAR("Q_NVINHSMICPERM", 1),
        DEF_VAR("Q_NVKINT", 1),
        DEF_VAR("Q_NVKVINTSET", 2),
        DEF_VAR("Q_NVLOCACC", 6),
        DEF_VAR("Q_NVSBFBPERM", 1),
        DEF_VAR("Q_NVSBTSMPERM", 1),
        DEF_VAR("Q_ORIENTATION", 1),
        DEF_VAR("Q_OVERLAP", 1),
        DEF_VAR("Q_PBDSR", 1),
        DEF_VAR("Q_PLATFORM", 2),
        DEF_VAR("Q_RBC", 1),
        DEF_VAR("Q_RIU", 1),
        DEF_VAR("Q_SCALE", 2),
        DEF_VAR("Q_SECTIONTIMER", 1),
        DEF_VAR("Q_SLEEPSESSION", 1),
        DEF_VAR("Q_SRSTOP", 1),
        DEF_VAR("Q_SSCODE", 4),
        DEF_VAR("Q_STATUSLRBG", 2),
        DEF_VAR("Q_STOPLX", 1),
        DEF_VAR("Q_SUITABILITY", 2),
        DEF_VAR("Q_TEXT", 8),
        DEF_VAR("Q_TEXTCLASS", 2),
        DEF_VAR("Q_TEXTCONFIRM", 2),
        DEF_VAR("Q_TEXTDISPLAY", 1),
        DEF_VAR("Q_TEXTREPORT", 1),
        DEF_VAR("Q_TRACKINIT", 1),
        DEF_VAR("Q_UPDOWN", 1),
        DEF_VAR("Q_VBCO", 1),
        DEF_VAR("T_CYCLOC", 8),
        DEF_VAR("T_CYCRQST", 8),
        DEF_VAR("T_LSSMA", 8),
        DEF_VAR("T_ENDTIMER", 10),
        DEF_VAR("T_EMA", 10),
        DEF_VAR("T_MAR", 8),
        DEF_VAR("T_NVCONTACT", 8),
        DEF_VAR("T_NVOVTRP", 8),
        DEF_VAR("T_OL", 10),
        DEF_VAR("T_SECTIONTIMER", 10),
        DEF_VAR("T_TEXTDISPLAY", 10),
        DEF_VAR("T_TIMEOUTRQST", 10),
        DEF_VAR("T_TRAIN", 32),
        DEF_VAR("T_VBC", 8),
        DEF_VAR("V_AXLELOAD", 7),
        DEF_VAR("V_DIFF", 7),
        DEF_VAR("V_EMA", 7),
        DEF_VAR("V_LX", 7),
        DEF_VAR("V_MAIN", 7),
        DEF_VAR("V_MAMODE", 7),
        DEF_VAR("V_MAXTRAIN", 7),
        DEF_VAR("V_NVALLOWOVTRP", 7),
        DEF_VAR("V_NVKVINT", 7),
        DEF_VAR("V_NVLIMSUPERV", 7),
        DEF_VAR("V_NVONSIGHT", 7),
        DEF_VAR("V_NVSUPOVTRP", 7),
        DEF_VAR("V_NVREL", 7),
        DEF_VAR("V_NVSHUNT", 7),
        DEF_VAR("V_NVSTFF", 7),
        DEF_VAR("V_NVUNFIT", 7),
        DEF_VAR("V_RELEASEDP", 7),
        DEF_VAR("V_RELEASEOL", 7),
        DEF_VAR("V_REVERSE", 7),
        DEF_VAR("V_SM", 7),
        DEF_VAR("V_STATIC", 7),
        DEF_VAR("V_TRAIN", 7),
        DEF_VAR("V_TSR", 7),
        DEF_VAR_CUSTOM("X_TEXT", 8, NULL, NULL, dissect_var_ret_x_text),
        DEF_VAR("M_AXLELOAD", 7), // v1
        DEF_VAR("M_TRACKCONDBC", 4), // v1
        DEF_VAR("M_TRACTION", 8), // v1
        DEF_VAR("Q_TRACKDEL", 1), // v1
};

etcs_variable_t etcs_var_by_enum(const etcs_var_enum_t var) {
        return etcs_variables[var];
}

void etcs_register_variables(const int proto) {
        static hf_register_info hf[array_length(etcs_variables)];
        int hf_index = 0;
        for (size_t i = 0; i < array_length(etcs_variables); i++) {
                etcs_variable_t *var = &etcs_variables[i];
                register_var(var, &hf[hf_index++]);
        }
        proto_register_field_array(proto, hf, array_length(hf));
}

static void register_var(etcs_variable_t *var, hf_register_info *destination) {
        if (var->register_field == NULL) {
                register_var_generic(var, destination);
                return;
        }
        var->register_field(var, destination);
}

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
