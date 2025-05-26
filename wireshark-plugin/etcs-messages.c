#include "etcs-common.h"

#define DISSECTOR_MESSAGE(id) static void dissect_message_ ## id (tvbuff_t *tvb, proto_tree *tree, unsigned *offset, _U_ etcs_version_t version)

#define DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(id) DISSECTOR_MESSAGE(id) { \
        DISSECT_VAR(NID_MESSAGE); \
        DISSECT_VAR(L_MESSAGE); \
        DISSECT_VAR(T_TRAIN); \
        DISSECT_VAR(M_ACK); \
        DISSECT_VAR(NID_LRBG); \
}

#define DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(id) DISSECTOR_MESSAGE(id) { \
        DISSECT_VAR(NID_MESSAGE); \
        DISSECT_VAR(L_MESSAGE); \
        DISSECT_VAR(T_TRAIN); \
        DISSECT_VAR(NID_ENGINE); \
}

#define DEF_MESSAGE_TO_TRAIN(id, name) { \
        id, \
        name, \
        "Message " #id ": " name, \
        MESSAGE_TRACK_TO_TRAIN, \
        0, \
        "etcs.radio.message_" #id, \
        dissect_message_ ## id \
}

#define DEF_MESSAGE_TO_TRACK(id, name) { \
        id, \
        name, \
        "Message " #id ": " name, \
        MESSAGE_TRAIN_TO_TRACK, \
        0, \
        "etcs.radio.message_" #id, \
        dissect_message_ ## id \
}

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(129)

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(130)

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(131)

DISSECTOR_MESSAGE(132) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        if (version.major == 1) {
                DISSECT_VAR(Q_TRACKDEL_V1);
        } else {
                DISSECT_VAR(Q_MARQSTREASON);
        }
}

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(133)

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(136)

DISSECTOR_MESSAGE(137) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE(138) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE(146) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE(147) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(NID_EM);
        DISSECT_VAR(Q_EMERGENCYSTOP);
}

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(149)

DISSECTOR_MESSAGE(150) {
        const bool old_version =
                version.major == 1
                || (version.major == 2 && version.minor == 0)
                || (version.major == 2 && version.minor == 1)
                || (version.major == 2 && version.minor == 2);
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        if (old_version) {
        } else {
                DISSECT_VAR(Q_DESK);
        }
}

DISSECTOR_MESSAGE(153) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_BG);
        DISSECT_VAR(Q_INFILL);
}

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(154)

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(155)

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(156)

DISSECTOR_MESSAGE(157) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(Q_STATUSLRBG);
}

DISSECTOR_MESSAGE(158) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(NID_ENGINE);
        DISSECT_VAR(NID_TEXTMESSAGE);
}

DISSECTOR_MESSAGE_TO_TRACK_NO_VARS(159)

DISSECTOR_MESSAGE(2) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_SR);
}

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(3)

DISSECTOR_MESSAGE(4) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_REF);
        DISSECT_VAR(V_SM);
}

DISSECTOR_MESSAGE(5) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(6)

DISSECTOR_MESSAGE(7) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE(8) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(9)

DISSECTOR_MESSAGE(15) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(NID_EM);
        DISSECT_VAR(Q_SCALE);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(D_REF);
        }
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR(D_EMERGENCYSTOP);
}

DISSECTOR_MESSAGE(16) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(NID_EM);
}

DISSECTOR_MESSAGE(18) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(NID_EM);
}

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(24)

DISSECTOR_MESSAGE(27) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE(28) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(T_TRAIN);
}

DISSECTOR_MESSAGE(32) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(M_VERSION);
}

DISSECTOR_MESSAGE(33) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_REF);
}

DISSECTOR_MESSAGE(34) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(Q_SCALE);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(D_REF);
        }
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR(D_TAFDISPLAY);
        DISSECT_VAR(L_TAFDISPLAY);
}

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(37)

DISSECTOR_MESSAGE(38) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        // special: no NID_LRBG
}

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(39)

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(40)

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(41)

DISSECTOR_MESSAGE_TO_TRAIN_NO_VARS(43)

DISSECTOR_MESSAGE(45) {
        DISSECT_VAR(NID_MESSAGE);
        DISSECT_VAR(L_MESSAGE);
        DISSECT_VAR(T_TRAIN);
        DISSECT_VAR(M_ACK);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(Q_ORIENTATION);
}

static etcs_message_t etcs_messages_raw[] = {
        // train to track
        DEF_MESSAGE_TO_TRACK(129, "Validated Train Data"),
        DEF_MESSAGE_TO_TRACK(130, "Request for Shunting"),
        DEF_MESSAGE_TO_TRACK(131, "Request for Supervised Manoeuvre"),
        DEF_MESSAGE_TO_TRACK(132, "MA Request"),
        DEF_MESSAGE_TO_TRACK(133, "Safe consist length information for Supervised Manoeuvre"),
        DEF_MESSAGE_TO_TRACK(136, "Train Position Report"),
        DEF_MESSAGE_TO_TRACK(137, "Request to shorten MA is granted"),
        DEF_MESSAGE_TO_TRACK(138, "Request to shorten MA is rejected"),
        DEF_MESSAGE_TO_TRACK(146, "Acknowledgement"),
        DEF_MESSAGE_TO_TRACK(147, "Acknowledgement of Emergency Stop"),
        DEF_MESSAGE_TO_TRACK(149, "Track Ahead Free Granted"),
        DEF_MESSAGE_TO_TRACK(150, "End of Mission"),
        DEF_MESSAGE_TO_TRACK(153, "Radio infill request"),
        DEF_MESSAGE_TO_TRACK(154, "No compatible version supported"),
        DEF_MESSAGE_TO_TRACK(155, "Initiation of a communication session"),
        DEF_MESSAGE_TO_TRACK(156, "Termination of a communication session"),
        DEF_MESSAGE_TO_TRACK(157, "SoM Position Report"),
        DEF_MESSAGE_TO_TRACK(158, "Text message acknowledged by driver"),
        DEF_MESSAGE_TO_TRACK(159, "Session Established"),
        // track to train
        DEF_MESSAGE_TO_TRAIN(2, "SR Authorisation"),
        DEF_MESSAGE_TO_TRAIN(3, "Movement Authority"),
        DEF_MESSAGE_TO_TRAIN(4, "SM Authorisation"),
        DEF_MESSAGE_TO_TRAIN(5, "SM Refused"),
        DEF_MESSAGE_TO_TRAIN(6, "Recognition of exit from TRIP mode"),
        DEF_MESSAGE_TO_TRAIN(7, "Acknowledgement of safe consist length info for SM"),
        DEF_MESSAGE_TO_TRAIN(8, "Acknowledgement of Train Data"),
        DEF_MESSAGE_TO_TRAIN(9, "Request to Shorten MA"),
        DEF_MESSAGE_TO_TRAIN(15, "Conditional Emergency Stop"),
        DEF_MESSAGE_TO_TRAIN(16, "Unconditional Emergency Stop"),
        DEF_MESSAGE_TO_TRAIN(18, "Revocation of Emergency Stop"),
        DEF_MESSAGE_TO_TRAIN(24, "General message"),
        DEF_MESSAGE_TO_TRAIN(27, "SH Refused"),
        DEF_MESSAGE_TO_TRAIN(28, "SH Authorised"),
        DEF_MESSAGE_TO_TRAIN(33, "MA with Shifted Location Reference"),
        DEF_MESSAGE_TO_TRAIN(34, "Track Ahead Free Request"),
        DEF_MESSAGE_TO_TRAIN(37, "Infill MA"),
        DEF_MESSAGE_TO_TRAIN(40, "Train Rejected"),
        DEF_MESSAGE_TO_TRAIN(32, "RBC/RIU System Version"),
        DEF_MESSAGE_TO_TRAIN(38, "Acknowledgement of session establishment"),
        DEF_MESSAGE_TO_TRAIN(39, "Acknowledgement of termination of a communication session"),
        DEF_MESSAGE_TO_TRAIN(41, "Train Accepted"),
        DEF_MESSAGE_TO_TRAIN(43, "SoM position report confirmed by RBC"),
        DEF_MESSAGE_TO_TRAIN(45, "Assignment of coordinate system"),
};

static etcs_message_t *etcs_messages[256];

static value_string etcs_nid_message_values[array_length(etcs_messages_raw) + 1];

static void init_message_info(void) {
        for (size_t i = 0; i < array_length(etcs_messages); i++) {
                etcs_messages[i] = NULL;
        }
        for (size_t i = 0; i < array_length(etcs_messages_raw); i++) {
                const uint8_t nid_message = etcs_messages_raw[i].nid_message;
                etcs_messages[nid_message] = &etcs_messages_raw[i];
        }
        for (size_t i = 0; i < array_length(etcs_messages_raw); i++) {
                const value_string value = {
                        etcs_messages_raw[i].nid_message,
                        etcs_messages_raw[i].name
                };
                etcs_nid_message_values[i] = value;
        }
        const value_string terminator = {0, NULL};
        etcs_nid_message_values[array_length(etcs_messages_raw)] = terminator;
}

static etcs_message_t etcs_unknown_message = {
        0, // dummy value,
        "Unknown message",
        "Unknown message",
        MESSAGE_ANY_DIRECTION,
        0,
        "etcs.unknown_message",
        NULL
};
