#include "etcs-common.h"

#include <wsutil/array.h>

#define DISSECTOR_PACKET_TO_TRAIN(id) static etcs_packet_dissected_t dissect_packet_to_train_ ## id (tvbuff_t *tvb, proto_tree *tree, unsigned *offset, _U_ etcs_version_t version)

#define DISSECTOR_PACKET_TO_TRACK(id) static etcs_packet_dissected_t dissect_packet_to_track_ ## id (tvbuff_t *tvb, proto_tree *tree, unsigned *offset, _U_ etcs_version_t version)

#define PACKET_ITEM_NAME(id, name) "Packet " # id ": " name

#define SET_PACKET_NAME(id, name) proto_item_set_text(proto_tree_get_parent(tree), PACKET_ITEM_NAME(id, name))

#define DEF_PACKET_TO_TRACK(id, name) { \
        id, \
        PACKET_ITEM_NAME(id, name), \
        0, \
        0, \
        "etcs.train_to_track.packet_" #id, \
        dissect_packet_to_track_ ## id \
}

#define DEF_PACKET_TO_TRAIN(id, name) { \
        id, \
        PACKET_ITEM_NAME(id, name), \
        0, \
        0, \
        "etcs.track_to_train.packet_" #id, \
        dissect_packet_to_train_ ## id \
}

static void initialize_packets(etcs_packet_t packets[], size_t size, etcs_packet_t *lookup[]);

DISSECTOR_PACKET_TO_TRAIN(0) {
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(NID_VBCMK);
        return (etcs_packet_dissected_t){-1};
}

DISSECTOR_PACKET_TO_TRAIN(2) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(M_VERSION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(3) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        uint64_t n;
        uint64_t m;
        uint64_t l;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_VALIDNV);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(V_NVSHUNT);
        DISSECT_VAR(V_NVSTFF);
        DISSECT_VAR(V_NVONSIGHT);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(V_NVLIMSUPERV);
        }
        DISSECT_VAR(V_NVUNFIT);
        DISSECT_VAR(V_NVREL);
        DISSECT_VAR(D_NVROLL);
        DISSECT_VAR(Q_NVSBTSMPERM);
        DISSECT_VAR(Q_NVEMRRLS);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(Q_NVGUIPERM);
                DISSECT_VAR(Q_NVSBFBPERM);
                DISSECT_VAR(Q_NVINHSMICPERM);
        }
        DISSECT_VAR(V_NVALLOWOVTRP);
        DISSECT_VAR(V_NVSUPOVTRP);
        DISSECT_VAR(D_NVOVTRP);
        DISSECT_VAR(T_NVOVTRP);
        DISSECT_VAR(D_NVPOTRP);
        DISSECT_VAR(M_NVCONTACT);
        DISSECT_VAR(T_NVCONTACT);
        DISSECT_VAR(M_NVDERUN);
        DISSECT_VAR(D_NVSTFF);
        DISSECT_VAR(Q_NVDRIVER_ADHES);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(A_NVMAXREDADH1);
                DISSECT_VAR(A_NVMAXREDADH2);
                DISSECT_VAR(A_NVMAXREDADH3);
                DISSECT_VAR(Q_NVLOCACC);
                DISSECT_VAR(M_NVAVADH);
                DISSECT_VAR(M_NVEBCL);
                DISSECT_VAR_RET(Q_NVKINT, &value);
                if (value == 1) {
                        DISSECT_VAR_RET(Q_NVKVINTSET, &value);
                        if (value == 1) {
                                DISSECT_VAR(A_NVP12);
                                DISSECT_VAR(A_NVP23);
                        }
                        DISSECT_VAR(V_NVKVINT);
                        DISSECT_VAR(M_NVKVINT);
                        if (value == 1) {
                                DISSECT_VAR(M_NVKVINT);
                        }
                        DISSECT_VAR_RET(N_ITER, &n);
                        for (; n > 0; n--) {
                                DISSECT_VAR(V_NVKVINT);
                                DISSECT_VAR(M_NVKVINT);
                                if (value == 1) {
                                        DISSECT_VAR(M_NVKVINT);
                                }
                        }
                        DISSECT_VAR_RET(N_ITER, &k);
                        for (; k > 0; k--) {
                                DISSECT_VAR_RET(Q_NVKVINTSET, &value);
                                if (value == 1) {
                                        DISSECT_VAR(A_NVP12);
                                        DISSECT_VAR(A_NVP23);
                                }
                                DISSECT_VAR(V_NVKVINT);
                                DISSECT_VAR(M_NVKVINT);
                                if (value == 1) {
                                        DISSECT_VAR(M_NVKVINT);
                                }
                                DISSECT_VAR_RET(N_ITER, &m);
                                for (; m > 0; m--) {
                                        DISSECT_VAR(V_NVKVINT);
                                        DISSECT_VAR(M_NVKVINT);
                                        if (value == 1) {
                                                DISSECT_VAR(M_NVKVINT);
                                        }
                                }
                        }
                        DISSECT_VAR(L_NVKRINT);
                        DISSECT_VAR(M_NVKRINT);
                        DISSECT_VAR_RET(N_ITER, &l);
                        for (; l > 0; l--) {
                                DISSECT_VAR(L_NVKRINT);
                                DISSECT_VAR(M_NVKRINT);
                        }
                        DISSECT_VAR(M_NVKTINT);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(5) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_LINK);
        DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(NID_BG);
        DISSECT_VAR(Q_LINKORIENTATION);
        DISSECT_VAR(Q_LINKREACTION);
        DISSECT_VAR(Q_LOCACC);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(D_LINK);
                DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_C);
                }
                DISSECT_VAR(NID_BG);
                DISSECT_VAR(Q_LINKORIENTATION);
                DISSECT_VAR(Q_LINKREACTION);
                DISSECT_VAR(Q_LOCACC);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(6) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(Q_VBCO, &value);
        DISSECT_VAR(NID_VBCMK);
        DISSECT_VAR(NID_C);
        if (value == 1) {
                DISSECT_VAR(T_VBC);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(12) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(V_MAIN);
        DISSECT_VAR(V_EMA);
        DISSECT_VAR(T_EMA);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(L_SECTION);
                DISSECT_VAR_RET(Q_SECTIONTIMER, &value);
                if (value == 1) {
                        DISSECT_VAR(T_SECTIONTIMER);
                        DISSECT_VAR(D_SECTIONTIMERSTOPLOC);
                }
        }
        DISSECT_VAR(L_ENDSECTION);
        DISSECT_VAR_RET(Q_SECTIONTIMER, &value);
        if (value == 1) {
                DISSECT_VAR(T_SECTIONTIMER);
                DISSECT_VAR(D_SECTIONTIMERSTOPLOC);
        }
        DISSECT_VAR_RET(Q_ENDTIMER, &value);
        if (value == 1) {
                DISSECT_VAR(T_ENDTIMER);
                DISSECT_VAR(D_ENDTIMERSTARTLOC);
        }
        DISSECT_VAR_RET(Q_DANGERPOINT, &value);
        if (value == 1) {
                DISSECT_VAR(D_DP);
                DISSECT_VAR(V_RELEASEDP);
        }
        DISSECT_VAR_RET(Q_OVERLAP, &value);
        if (value == 1) {
                DISSECT_VAR(D_STARTOL);
                DISSECT_VAR(T_OL);
                DISSECT_VAR(D_OL);
                DISSECT_VAR(V_RELEASEOL);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(13) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(NID_BG);
        DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(NID_BG);
        DISSECT_VAR(D_SR);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_C);
                }
                DISSECT_VAR(NID_BG);
                DISSECT_VAR(D_SR);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(15) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(V_EMA);
        DISSECT_VAR(T_EMA);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(L_SECTION);
                DISSECT_VAR_RET(Q_SECTIONTIMER, &value);
                if (value == 1) {
                        DISSECT_VAR(T_SECTIONTIMER);
                        DISSECT_VAR(D_SECTIONTIMERSTOPLOC);
                }
        }
        DISSECT_VAR(L_ENDSECTION);
        DISSECT_VAR_RET(Q_SECTIONTIMER, &value);
        if (value == 1) {
                DISSECT_VAR(T_SECTIONTIMER);
                DISSECT_VAR(D_SECTIONTIMERSTOPLOC);
        }
        DISSECT_VAR_RET(Q_ENDTIMER, &value);
        if (value == 1) {
                DISSECT_VAR(T_ENDTIMER);
                DISSECT_VAR(D_ENDTIMERSTARTLOC);
        }
        DISSECT_VAR_RET(Q_DANGERPOINT, &value);
        if (value == 1) {
                DISSECT_VAR(D_DP);
                DISSECT_VAR(V_RELEASEDP);
        }
        DISSECT_VAR_RET(Q_OVERLAP, &value);
        if (value == 1) {
                DISSECT_VAR(D_STARTOL);
                DISSECT_VAR(T_OL);
                DISSECT_VAR(D_OL);
                DISSECT_VAR(V_RELEASEOL);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(16) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(L_SECTION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(21) {
        uint64_t l_packet;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_GRADIENT);
        DISSECT_VAR(Q_GDIR);
        DISSECT_VAR(G_A);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(D_GRADIENT);
                DISSECT_VAR(Q_GDIR);
                DISSECT_VAR(G_A);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(27) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        uint64_t m;
        uint64_t n;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_STATIC);
        DISSECT_VAR(V_STATIC);
        DISSECT_VAR(Q_FRONT);
        DISSECT_VAR_RET(N_ITER, &n);
        for (; n > 0; n--) {
                if (version.major == 1) {
                        DISSECT_VAR(NC_DIFF);
                } else {
                        DISSECT_VAR_RET(Q_DIFF, &value);
                        if (value == 0) {
                                DISSECT_VAR(NC_CDDIFF);
                        } else if (value == 1 || value == 2) {
                                DISSECT_VAR(NC_DIFF);
                        }
                }
                DISSECT_VAR(V_DIFF);
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(D_STATIC);
                DISSECT_VAR(V_STATIC);
                DISSECT_VAR(Q_FRONT);
                DISSECT_VAR_RET(N_ITER, &m);
                for (; m > 0; m--) {
                        if (version.major == 1) {
                                DISSECT_VAR(NC_DIFF);
                        } else {
                                DISSECT_VAR_RET(Q_DIFF, &value);
                                if (value == 0) {
                                        DISSECT_VAR(NC_CDDIFF);
                                } else if (value == 1 || value == 2) {
                                        DISSECT_VAR(NC_DIFF);
                                }
                        }
                        DISSECT_VAR(V_DIFF);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(31) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_RBCTR);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_RBC);
        DISSECT_VAR(Q_SLEEPSESSION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(32) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_RBC);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_RBC);
        DISSECT_VAR(Q_SLEEPSESSION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(39) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_TRACTION);
        if (version.major == 1) {
                DISSECT_VAR(M_TRACTION_V1);
        } else {
                DISSECT_VAR_RET(M_VOLTAGE, &value);
                if (value != 0) {
                        DISSECT_VAR(NID_CTRACTION);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(40) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_CURRENT);
        DISSECT_VAR(M_CURRENT);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(41) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_LEVELTR);
        DISSECT_VAR_RET(M_LEVELTR, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        DISSECT_VAR(L_ACKLEVELTR);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(M_LEVELTR, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_NTC);
                }
                DISSECT_VAR(L_ACKLEVELTR);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(42) {
        if (version.major == 1 || (version.major == 2 && version.minor <= 2)) {
                SET_PACKET_NAME(42, "Session Management");
        }
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_RBC);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_RBC);
        DISSECT_VAR(NID_RADIO);
        DISSECT_VAR(Q_SLEEPSESSION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(44) {
        uint64_t value;
        uint64_t l_packet;
        const unsigned start_offset = *offset;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        if (version.major == 1) {
        } else {
                DISSECT_VAR_RET(NID_XUSER, &value);
                if (value == 102) {
                        DISSECT_VAR(NID_NTC);
                }
        }
        // TODO: display "other data"
        *offset = start_offset + l_packet;
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(45) {
        if (version.major < 3) {
                SET_PACKET_NAME(45, "Radio Network registration");
        }
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        if (version.major == 1 || version.major == 2) {
                DISSECT_VAR(NID_MN);
        } else {
                DISSECT_VAR(Q_NETWORKTYPE);
                DISSECT_VAR_RET(Q_NETWORKTYPE, &value);
                if (value == 1 || value == 2) {
                        DISSECT_VAR(NID_MN);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(46) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(M_LEVELTR, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(M_LEVELTR, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_NTC);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(49) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_C);
                }
                DISSECT_VAR(NID_BG);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(51) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        uint64_t n;
        uint64_t m;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                if (version.major == 1) {
                } else {
                        DISSECT_VAR(D_TRACKINIT);
                }
        } else if (value == 0) {
                DISSECT_VAR(D_AXLELOAD);
                DISSECT_VAR(L_AXLELOAD);
                DISSECT_VAR(Q_FRONT);
                DISSECT_VAR_RET(N_ITER, &n);
                for (; n > 0; n--) {
                        if (version.major == 1) {
                                DISSECT_VAR(M_AXLELOAD_V1);
                        } else {
                                DISSECT_VAR(M_AXLELOADCAT);
                        }
                        DISSECT_VAR(V_AXLELOAD);
                }
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_AXLELOAD);
                        DISSECT_VAR(L_AXLELOAD);
                        DISSECT_VAR(Q_FRONT);
                        DISSECT_VAR_RET(N_ITER, &m);
                        for (; m > 0; m--) {
                                DISSECT_VAR(M_AXLELOADCAT);
                                DISSECT_VAR(V_AXLELOAD);
                        }
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(52) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                DISSECT_VAR(D_TRACKINIT);
        } else if (value == 0) {
                DISSECT_VAR(D_PBD);
                DISSECT_VAR(Q_GDIR);
                DISSECT_VAR(G_PBDSR);
                DISSECT_VAR(Q_PBDSR);
                DISSECT_VAR(D_PBDSR);
                DISSECT_VAR(L_PBDSR);
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_PBD);
                        DISSECT_VAR(Q_GDIR);
                        DISSECT_VAR(G_PBDSR);
                        DISSECT_VAR(Q_PBDSR);
                        DISSECT_VAR(D_PBDSR);
                        DISSECT_VAR(L_PBDSR);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(57) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(T_MAR);
        DISSECT_VAR(T_TIMEOUTRQST);
        DISSECT_VAR(T_CYCRQST);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(58) {
        uint64_t l_packet;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(T_CYCLOC);
        DISSECT_VAR(D_CYCLOC);
        DISSECT_VAR(M_LOC);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(D_LOC);
                DISSECT_VAR(Q_LGTLOC);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(63) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_C);
                }
                DISSECT_VAR(NID_BG);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(64) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(65) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(NID_TSR);
        DISSECT_VAR(D_TSR);
        DISSECT_VAR(L_TSR);
        DISSECT_VAR(Q_FRONT);
        DISSECT_VAR(V_TSR);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(66) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(NID_TSR);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(67) {
        uint64_t l_packet;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_TRACKCOND);
        DISSECT_VAR(L_TRACKCOND);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(D_TRACKCOND);
                DISSECT_VAR(L_TRACKCOND);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(68) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                DISSECT_VAR(D_TRACKINIT);
        } else if (value == 0) {
                DISSECT_VAR(D_TRACKCOND);
                DISSECT_VAR(L_TRACKCOND);
                DISSECT_VAR(M_TRACKCOND);
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_TRACKCOND);
                        DISSECT_VAR(L_TRACKCOND);
                        DISSECT_VAR(M_TRACKCOND);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(69) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                DISSECT_VAR(D_TRACKINIT);
        } else if (value == 0) {
                DISSECT_VAR(D_TRACKCOND);
                DISSECT_VAR(L_TRACKCOND);
                DISSECT_VAR(M_PLATFORM);
                DISSECT_VAR(Q_PLATFORM);
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_TRACKCOND);
                        DISSECT_VAR(L_TRACKCOND);
                        DISSECT_VAR(M_PLATFORM);
                        DISSECT_VAR(Q_PLATFORM);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(70) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                DISSECT_VAR(D_TRACKINIT);
        } else if (value == 0) {
                DISSECT_VAR(D_SUITABILITY);
                DISSECT_VAR_RET(Q_SUITABILITY, &value);
                if (version.major == 1) {
                        if (value == 1) {
                                DISSECT_VAR(M_AXLELOAD_V1);
                        } else if (value == 2) {
                                DISSECT_VAR(M_TRACTION_V1);
                        }
                } else {
                        if (value == 0) {
                                DISSECT_VAR(M_LINEGAUGE);
                        } else if (value == 1) {
                                if (version.major == 2) {
                                        DISSECT_VAR(M_AXLELOADCAT);
                                } else {
                                        DISSECT_VAR(M_LINEAXLELOADCAT);
                                }
                        } else if (value == 2) {
                                DISSECT_VAR_RET(M_VOLTAGE, &value);
                                if (value != 0) {
                                        DISSECT_VAR(NID_CTRACTION);
                                }
                        }
                }
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_SUITABILITY);
                        DISSECT_VAR_RET(Q_SUITABILITY, &value);
                        if (version.major == 1) {
                                if (value == 1) {
                                        DISSECT_VAR(M_AXLELOAD_V1);
                                } else if (value == 2) {
                                        DISSECT_VAR(M_TRACTION_V1);
                                }
                        } else {
                                if (value == 0) {
                                        DISSECT_VAR(M_LINEGAUGE);
                                } else if (value == 1) {
                                        if (version.major == 2) {
                                                DISSECT_VAR(M_AXLELOADCAT);
                                        } else {
                                                DISSECT_VAR(M_LINEAXLELOADCAT);
                                        }
                                } else if (value == 2) {
                                        DISSECT_VAR_RET(M_VOLTAGE, &value);
                                        if (value != 0) {
                                                DISSECT_VAR(NID_CTRACTION);
                                        }
                                }
                        }
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(71) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_ADHESION);
        DISSECT_VAR(L_ADHESION);
        DISSECT_VAR(M_ADHESION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(72) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t l_text;
        if (version.major == 1) {
                // separate definition for version 1
                DISSECT_VAR(NID_PACKET);
                DISSECT_VAR(Q_DIR);
                DISSECT_VAR_RET(L_PACKET, &l_packet);
                DISSECT_VAR(Q_SCALE);
                DISSECT_VAR(Q_TEXTCLASS);
                DISSECT_VAR(Q_TEXTDISPLAY);
                DISSECT_VAR(D_TEXTDISPLAY);
                DISSECT_VAR(M_MODETEXTDISPLAY);
                DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_NTC);
                }
                DISSECT_VAR(L_TEXTDISPLAY);
                DISSECT_VAR(T_TEXTDISPLAY);
                DISSECT_VAR(M_MODETEXTDISPLAY);
                DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_NTC);
                }
                DISSECT_VAR_RET(Q_TEXTCONFIRM, &value);
                DISSECT_VAR_RET(L_TEXT, &l_text);
                for (; l_text > 0; l_text--) {
                        DISSECT_VAR(X_TEXT);
                }
        } else {
                // use the same code as packet 73 from the newer spec
                DISSECT_VAR(NID_PACKET);
                DISSECT_VAR(Q_DIR);
                DISSECT_VAR_RET(L_PACKET, &l_packet);
                DISSECT_VAR(Q_SCALE);
                DISSECT_VAR(Q_TEXTCLASS);
                DISSECT_VAR(Q_TEXTDISPLAY);
                DISSECT_VAR(D_TEXTDISPLAY);
                DISSECT_VAR(M_MODETEXTDISPLAY);
                DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_NTC);
                }
                DISSECT_VAR(L_TEXTDISPLAY);
                DISSECT_VAR(T_TEXTDISPLAY);
                DISSECT_VAR(M_MODETEXTDISPLAY);
                DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_NTC);
                }
                DISSECT_VAR_RET(Q_TEXTCONFIRM, &value);
                if (value != 0) {
                        DISSECT_VAR(Q_CONFTEXTDISPLAY);
                        DISSECT_VAR_RET(Q_TEXTREPORT, &value);
                        if (value == 1) {
                                DISSECT_VAR(NID_TEXTMESSAGE);
                                DISSECT_VAR(NID_C);
                                DISSECT_VAR(NID_RBC);
                        }
                }
                DISSECT_VAR_RET(L_TEXT, &l_text);
                for (; l_text > 0; l_text--) {
                        DISSECT_VAR(X_TEXT);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(73) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t l_text;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(Q_TEXTCLASS);
        DISSECT_VAR(Q_TEXTDISPLAY);
        DISSECT_VAR(D_TEXTDISPLAY);
        DISSECT_VAR(M_MODETEXTDISPLAY);
        DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        DISSECT_VAR(L_TEXTDISPLAY);
        DISSECT_VAR(T_TEXTDISPLAY);
        DISSECT_VAR(M_MODETEXTDISPLAY);
        DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        DISSECT_VAR_RET(Q_TEXTCONFIRM, &value);
        if (value != 0) {
                DISSECT_VAR(Q_CONFTEXTDISPLAY);
                DISSECT_VAR_RET(Q_TEXTREPORT, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_TEXTMESSAGE);
                        DISSECT_VAR(NID_C);
                        DISSECT_VAR(NID_RBC);
                }
        }
        DISSECT_VAR_RET(L_TEXT, &l_text);
        for (; l_text > 0; l_text--) {
                DISSECT_VAR(X_TEXT);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(74) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(Q_TEXTCLASS);
        DISSECT_VAR(Q_TEXTDISPLAY);
        DISSECT_VAR(D_TEXTDISPLAY);
        DISSECT_VAR(M_MODETEXTDISPLAY);
        DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        DISSECT_VAR(L_TEXTDISPLAY);
        DISSECT_VAR(T_TEXTDISPLAY);
        DISSECT_VAR(M_MODETEXTDISPLAY);
        DISSECT_VAR_RET(M_LEVELTEXTDISPLAY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        DISSECT_VAR_RET(Q_TEXTCONFIRM, &value);
        if (value != 0) {
                DISSECT_VAR(Q_CONFTEXTDISPLAY);
                DISSECT_VAR_RET(Q_TEXTREPORT, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_TEXTMESSAGE);
                        DISSECT_VAR(NID_C);
                        DISSECT_VAR(NID_RBC);
                }
        }
        DISSECT_VAR(Q_TEXT);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(76) {
        // same as packet 74, but only in some older versions
        return dissect_packet_to_train_74(tvb, tree, offset, version);
}

DISSECTOR_PACKET_TO_TRAIN(79) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(NID_BG);
        DISSECT_VAR(D_POSOFF);
        DISSECT_VAR(Q_MPOSITION);
        if (version.major == 1) {
                DISSECT_VAR(M_POSITION_V1);
        } else {
                DISSECT_VAR(M_POSITION);
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
                if (value == 1) {
                        DISSECT_VAR(NID_C);
                }
                DISSECT_VAR(NID_BG);
                DISSECT_VAR(D_POSOFF);
                DISSECT_VAR(Q_MPOSITION);
                if (version.major == 1) {
                        DISSECT_VAR(M_POSITION_V1);
                } else {
                        DISSECT_VAR(M_POSITION);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(80) {
        uint64_t l_packet;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_MAMODE);
        DISSECT_VAR(M_MAMODE);
        DISSECT_VAR(V_MAMODE);
        DISSECT_VAR(L_MAMODE);
        DISSECT_VAR(L_ACKMAMODE);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(Q_MAMODE);
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(D_MAMODE);
                DISSECT_VAR(M_MAMODE);
                DISSECT_VAR(V_MAMODE);
                DISSECT_VAR(L_MAMODE);
                DISSECT_VAR(L_ACKMAMODE);
                if (version.major == 1) {
                } else {
                        DISSECT_VAR(Q_MAMODE);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(88) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(NID_LX);
        DISSECT_VAR(D_LX);
        DISSECT_VAR(L_LX);
        DISSECT_VAR_RET(Q_LXSTATUS, &value);
        if (value == 1) {
                DISSECT_VAR(V_LX);
                DISSECT_VAR_RET(Q_STOPLX, &value);
                if (value == 1) {
                        DISSECT_VAR(L_STOPLX);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(90) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(NID_BG);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(131) {
        if (version.major < 3 || (version.major == 2 && version.minor < 3)) {
                SET_PACKET_NAME(131, "RBC transition order");
        }
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_RBCTR);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_RBC);
        DISSECT_VAR(NID_RADIO);
        DISSECT_VAR(Q_SLEEPSESSION);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(132) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_ASPECT);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(133) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(Q_RIU);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_RIU);
        DISSECT_VAR(NID_RADIO);
        DISSECT_VAR(D_INFILL);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_BG);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(134) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(NID_LOOP);
        DISSECT_VAR(D_LOOP);
        DISSECT_VAR(L_LOOP);
        DISSECT_VAR(Q_LOOPDIR);
        DISSECT_VAR(Q_SSCODE);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(135) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(136) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(Q_NEWCOUNTRY, &value);
        if (value == 1) {
                DISSECT_VAR(NID_C);
        }
        DISSECT_VAR(NID_BG);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(137) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SRSTOP);
        return (etcs_packet_dissected_t){(int) l_packet};
}


DISSECTOR_PACKET_TO_TRAIN(138) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_STARTREVERSE);
        DISSECT_VAR(L_REVERSEAREA);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(139) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_REVERSE);
        DISSECT_VAR(V_REVERSE);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(140) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(NID_OPERATIONAL);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(141) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_GDIR);
        DISSECT_VAR(G_TSR);
        return (etcs_packet_dissected_t){(int) l_packet};
}


DISSECTOR_PACKET_TO_TRAIN(143) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_RIU);
        DISSECT_VAR(NID_C);
        DISSECT_VAR(NID_RIU);
        DISSECT_VAR(NID_RADIO);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(145) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(180) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(Q_LSSMA, &value);
        if (value == 1) {
                DISSECT_VAR(T_LSSMA);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(181) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(200) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(NID_VBCMK);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(203) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t n;
        uint64_t k;
        uint64_t m;
        uint64_t l;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_NVGUIPERM);
        DISSECT_VAR(Q_NVSBFBPERM);
        DISSECT_VAR(Q_NVINHSMICPERM);
        DISSECT_VAR(A_NVMAXREDADH1);
        DISSECT_VAR(A_NVMAXREDADH2);
        DISSECT_VAR(A_NVMAXREDADH3);
        DISSECT_VAR(M_NVAVADH);
        DISSECT_VAR(M_NVEBCL);
        DISSECT_VAR_RET(Q_NVKINT, &value);
        if (value == 1) {
                DISSECT_VAR_RET(Q_NVKVINTSET, &value);
                if (value == 1) {
                        DISSECT_VAR(A_NVP12);
                        DISSECT_VAR(A_NVP23);
                }
                DISSECT_VAR(V_NVKVINT);
                DISSECT_VAR(M_NVKVINT);
                if (value == 1) {
                        DISSECT_VAR(M_NVKVINT);
                }
                DISSECT_VAR_RET(N_ITER, &n);
                for (; n > 0; n--) {
                        DISSECT_VAR(V_NVKVINT);
                        DISSECT_VAR(M_NVKVINT);
                        if (value == 1) {
                                DISSECT_VAR(M_NVKVINT);
                        }
                }
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR_RET(Q_NVKVINTSET, &value);
                        if (value == 1) {
                                DISSECT_VAR(A_NVP12);
                                DISSECT_VAR(A_NVP23);
                        }
                        DISSECT_VAR(V_NVKVINT);
                        DISSECT_VAR(M_NVKVINT);
                        if (value == 1) {
                                DISSECT_VAR(M_NVKVINT);
                        }
                        DISSECT_VAR_RET(N_ITER, &m);
                        for (; m > 0; m--) {
                                DISSECT_VAR(V_NVKVINT);
                                DISSECT_VAR(M_NVKVINT);
                                if (value == 1) {
                                        DISSECT_VAR(M_NVKVINT);
                                }
                        }
                }
                DISSECT_VAR(L_NVKRINT);
                DISSECT_VAR(M_NVKRINT);
                DISSECT_VAR_RET(N_ITER, &l);
                for (; l > 0; l--) {
                        DISSECT_VAR(L_NVKRINT);
                        DISSECT_VAR(M_NVKRINT);
                }
                DISSECT_VAR(M_NVKTINT);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(206) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                DISSECT_VAR(D_TRACKINIT);
        } else if (value == 0) {
                DISSECT_VAR(D_TRACKCOND);
                DISSECT_VAR(L_TRACKCOND);
                DISSECT_VAR(M_TRACKCONDBC_V1);
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_TRACKCOND);
                        DISSECT_VAR(L_TRACKCOND);
                        DISSECT_VAR(M_TRACKCONDBC_V1);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(207) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR_RET(Q_TRACKINIT, &value);
        if (value == 1) {
                DISSECT_VAR(D_TRACKINIT);
        } else if (value == 0) {
                DISSECT_VAR(D_SUITABILITY);
                DISSECT_VAR_RET(Q_SUITABILITY, &value);
                if (value == 0) {
                        DISSECT_VAR(M_LINEGAUGE);
                } else if (value == 1) {
                        DISSECT_VAR(M_AXLELOADCAT);
                } else if (value == 2) {
                        DISSECT_VAR_RET(M_VOLTAGE, &value);
                        if (value != 1) {
                                DISSECT_VAR(NID_CTRACTION);
                        }
                }
                DISSECT_VAR_RET(N_ITER, &k);
                for (; k > 0; k--) {
                        DISSECT_VAR(D_SUITABILITY);
                        DISSECT_VAR_RET(Q_SUITABILITY, &value);
                        if (value == 0) {
                                DISSECT_VAR(M_LINEGAUGE);
                        } else if (value == 1) {
                                DISSECT_VAR(M_AXLELOADCAT);
                        } else if (value == 2) {
                                DISSECT_VAR_RET(M_VOLTAGE, &value);
                                if (value != 1) {
                                        DISSECT_VAR(NID_CTRACTION);
                                }
                        }
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(239) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(D_TRACTION);
        DISSECT_VAR_RET(M_VOLTAGE, &value);
        if (value != 0) {
                DISSECT_VAR(NID_CTRACTION);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(245) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_NETWORKTYPE);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(254) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR(Q_DIR);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRAIN(255) {
        DISSECT_VAR(NID_PACKET);
        return (etcs_packet_dissected_t){-1};
}

static etcs_packet_t etcs_packets_to_train_raw[] = {
        DEF_PACKET_TO_TRAIN(0, "Virtual Balise Cover marker"),
        DEF_PACKET_TO_TRAIN(2, "System Version order"),
        DEF_PACKET_TO_TRAIN(3, "National Values"),
        DEF_PACKET_TO_TRAIN(5, "Linking"),
        DEF_PACKET_TO_TRAIN(6, "Virtual Balise Cover order"),
        DEF_PACKET_TO_TRAIN(12, "Level 1 Movement Authority"),
        DEF_PACKET_TO_TRAIN(13, "Staff Responsible distance information from loop"),
        DEF_PACKET_TO_TRAIN(15, "Level 2 Movement Authority"),
        DEF_PACKET_TO_TRAIN(16, "Repositioning Information"),
        DEF_PACKET_TO_TRAIN(21, "Gradient Profile"),
        DEF_PACKET_TO_TRAIN(27, "International Static Speed Profile"),
        DEF_PACKET_TO_TRAIN(31, "RBC transition order for RBC interfaced to FRMCS only"),
        DEF_PACKET_TO_TRAIN(32, "Session management for RBC interfaced to FRMCS only"),
        DEF_PACKET_TO_TRAIN(39, "Track Condition Change of traction system"),
        DEF_PACKET_TO_TRAIN(40, "Track Condition Change of allowed current consumption"),
        DEF_PACKET_TO_TRAIN(41, "Level Transition Order"),
        DEF_PACKET_TO_TRAIN(42, "Session Management for RBC interfaced to GSM-R"),
        DEF_PACKET_TO_TRAIN(44, "Data used by applications outside the ERTMS/ETCS system"),
        DEF_PACKET_TO_TRAIN(45, "Radio Network transition order"),
        DEF_PACKET_TO_TRAIN(46, "Conditional Level Transition Order"),
        DEF_PACKET_TO_TRAIN(49, "List of Balise Groups for SH Area"),
        DEF_PACKET_TO_TRAIN(51, "Axle load Speed Profile"),
        DEF_PACKET_TO_TRAIN(52, "Permitted Braking Distance Information"),
        DEF_PACKET_TO_TRAIN(57, "Movement Authority Request Parameters"),
        DEF_PACKET_TO_TRAIN(58, "Position Report Parameters"),
        DEF_PACKET_TO_TRAIN(63, "List of Balise Groups in SR Authority"),
        DEF_PACKET_TO_TRAIN(64, "Inhibition of revocable TSRs from balises in level 2"),
        DEF_PACKET_TO_TRAIN(65, "Temporary Speed Restriction"),
        DEF_PACKET_TO_TRAIN(66, "Temporary Speed Restriction Revocation"),
        DEF_PACKET_TO_TRAIN(67, "Track Condition Big Metal Masses"),
        DEF_PACKET_TO_TRAIN(68, "Track Condition"),
        DEF_PACKET_TO_TRAIN(69, "Track Condition Station Platforms"),
        DEF_PACKET_TO_TRAIN(70, "Route Suitability Data"),
        DEF_PACKET_TO_TRAIN(71, "Adhesion Factor"),
        DEF_PACKET_TO_TRAIN(72, "Packet for sending plain text messages"), // v2
        DEF_PACKET_TO_TRAIN(73, "Packet for sending plain text messages"),
        DEF_PACKET_TO_TRAIN(74, "Packet for sending fixed text messages"),
        DEF_PACKET_TO_TRAIN(76, "Packet for sending fixed text messages"), // v2
        DEF_PACKET_TO_TRAIN(79, "Geographical Position Information"),
        DEF_PACKET_TO_TRAIN(80, "Mode profile"),
        DEF_PACKET_TO_TRAIN(88, "Level crossing information"),
        DEF_PACKET_TO_TRAIN(90, "Track Ahead Free up to level 2 transition location"),
        DEF_PACKET_TO_TRAIN(131, "RBC transition order for RBC interfaced to GSM-R"),
        DEF_PACKET_TO_TRAIN(132, "Danger for Shunting information"),
        DEF_PACKET_TO_TRAIN(133, "Radio infill area information"),
        DEF_PACKET_TO_TRAIN(134, "EOLM Packet"),
        DEF_PACKET_TO_TRAIN(135, "Stop Shunting on desk opening"),
        DEF_PACKET_TO_TRAIN(136, "Infill location reference"),
        DEF_PACKET_TO_TRAIN(137, "Stop if in Staff Responsible"),
        DEF_PACKET_TO_TRAIN(138, "Reversing area information"),
        DEF_PACKET_TO_TRAIN(139, "Reversing supervision information"),
        DEF_PACKET_TO_TRAIN(140, "Train running number from RBC"),
        DEF_PACKET_TO_TRAIN(141, "Default Gradient for Temporary Speed Restriction"),
        DEF_PACKET_TO_TRAIN(143, "Session Management with neighbouring Radio Infill Unit"),
        DEF_PACKET_TO_TRAIN(145, "Inhibition of balise group message consistency reaction"),
        DEF_PACKET_TO_TRAIN(180, "LSSMA display toggle order"),
        DEF_PACKET_TO_TRAIN(181, "Generic LS function marker"),
        DEF_PACKET_TO_TRAIN(200, "Virtual Balise Cover marker"), // v2
        DEF_PACKET_TO_TRAIN(203, "National values for braking curves"), // v1
        DEF_PACKET_TO_TRAIN(206, "Track Condition"), // v1
        DEF_PACKET_TO_TRAIN(207, "Route Suitability data"), // v1
        DEF_PACKET_TO_TRAIN(239, "Track Condition Change of traction system"), // v1
        DEF_PACKET_TO_TRAIN(245, "Radio Network type"), // v2.3
        DEF_PACKET_TO_TRAIN(254, "Default balise, loop or RIU information"),
        DEF_PACKET_TO_TRAIN(255, "End of Information"),
};

static etcs_packet_t *etcs_packets_to_train[256];

DISSECTOR_PACKET_TO_TRACK(0) {
        const bool old_version =
                version.major == 1
                || (version.major == 2 && version.minor == 0)
                || (version.major == 2 && version.minor == 1);
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(D_LRBG);
        DISSECT_VAR(Q_DIRLRBG);
        DISSECT_VAR(Q_DLRBG);
        DISSECT_VAR(L_DOUBTOVER);
        DISSECT_VAR(L_DOUBTUNDER);
        DISSECT_VAR_RET(Q_INTEGRITY, &value);
        if (value == 1 || value == 2) {
                DISSECT_VAR(L_TRAININT);
        }
        DISSECT_VAR(V_TRAIN);
        DISSECT_VAR(Q_DIRTRAIN);
        if (old_version) {
                DISSECT_VAR(M_MODE_V1);
        } else {
                DISSECT_VAR(M_MODE);
        }
        DISSECT_VAR_RET(M_LEVEL, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(1) {
        const bool old_version =
                version.major == 1
                || (version.major == 2 && version.minor == 0)
                || (version.major == 2 && version.minor == 1);
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(Q_SCALE);
        DISSECT_VAR(NID_LRBG);
        DISSECT_VAR(NID_PRVLRBG);
        DISSECT_VAR(D_LRBG);
        DISSECT_VAR(Q_DIRLRBG);
        DISSECT_VAR(Q_DLRBG);
        DISSECT_VAR(L_DOUBTOVER);
        DISSECT_VAR(L_DOUBTUNDER);
        DISSECT_VAR_RET(Q_INTEGRITY, &value);
        if (value == 1 || value == 2) {
                DISSECT_VAR(L_TRAININT);
        }
        DISSECT_VAR(V_TRAIN);
        DISSECT_VAR(Q_DIRTRAIN);
        if (old_version) {
                DISSECT_VAR(M_MODE_V1);
        } else {
                DISSECT_VAR(M_MODE);
        }
        DISSECT_VAR_RET(M_LEVEL, &value);
        if (value == 1) {
                DISSECT_VAR(NID_NTC);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(2) {
        uint64_t l_packet;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(M_VERSION);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(M_VERSION);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(3) {
        uint64_t l_packet;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(NID_RADIO);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(4) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(M_ERROR);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(5) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(NID_OPERATIONAL);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(9) {
        uint64_t l_packet;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(NID_LTRBG);
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(10) {
        uint64_t l_packet;
        uint64_t value;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(Q_SAFECONSISTLENGTH, &value);
        if (value == 1) {
                DISSECT_VAR(L_CONSISTFRONTENGINEMIN);
                DISSECT_VAR(L_CONSISTFRONTENGINEMAX);
                DISSECT_VAR(L_CONSISTREARENGINENOM);
                DISSECT_VAR(L_CONSISTREARENGINEMIN);
                DISSECT_VAR(L_CONSISTREARENGINEMAX);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(11) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        if (version.major == 1) {
                DISSECT_VAR(NID_OPERATIONAL);
        } else {
                DISSECT_VAR(NC_CDTRAIN);
        }
        DISSECT_VAR(NC_TRAIN);
        DISSECT_VAR(L_TRAIN);
        DISSECT_VAR(V_MAXTRAIN);
        DISSECT_VAR(M_LOADINGGAUGE);
        if (version.major == 1) {
                DISSECT_VAR(M_AXLELOAD_V1);
        } else {
                DISSECT_VAR(M_AXLELOADCAT);
        }
        DISSECT_VAR(M_AIRTIGHT);
        if (version.major == 1) {
        } else {
                DISSECT_VAR(N_AXLE);
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                if (version.major == 1) {
                        DISSECT_VAR(M_TRACTION_V1);
                } else {
                        DISSECT_VAR_RET(M_VOLTAGE, &value);
                        if (value != 0) {
                                DISSECT_VAR(NID_CTRACTION);
                        }
                }
        }
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR(NID_NTC);
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(12) {
        uint64_t l_packet;
        uint64_t value;
        uint64_t k;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR(NC_CDTRAIN);
        DISSECT_VAR(NC_TRAIN);
        DISSECT_VAR(V_MAXTRAIN);
        DISSECT_VAR(M_LOADINGGAUGE);
        DISSECT_VAR(M_AXLELOADCAT);
        DISSECT_VAR(M_AIRTIGHT);
        DISSECT_VAR(N_AXLE);
        DISSECT_VAR_RET(N_ITER, &k);
        for (; k > 0; k--) {
                DISSECT_VAR_RET(M_VOLTAGE, &value);
                if (value != 0) {
                        DISSECT_VAR(NID_CTRACTION);
                }
        }
        return (etcs_packet_dissected_t){(int) l_packet};
}

DISSECTOR_PACKET_TO_TRACK(44) {
        uint64_t l_packet;
        uint64_t value;
        const unsigned start_offset = *offset;
        DISSECT_VAR(NID_PACKET);
        DISSECT_VAR_RET(L_PACKET, &l_packet);
        DISSECT_VAR_RET(NID_XUSER, &value);
        // TODO: display "other data"
        *offset = start_offset + l_packet;
        return (etcs_packet_dissected_t){(int) l_packet};
}

static etcs_packet_t etcs_packets_to_track_raw[] = {
        DEF_PACKET_TO_TRACK(0, "Position Report"),
        DEF_PACKET_TO_TRACK(1, "Position Report based on two balise groups"),
        DEF_PACKET_TO_TRACK(2, "Onboard supported system versions"),
        DEF_PACKET_TO_TRACK(3, "On-board telephone numbers"), // v1 + v2
        DEF_PACKET_TO_TRACK(4, "Error Reporting"),
        DEF_PACKET_TO_TRACK(5, "Train running number"),
        DEF_PACKET_TO_TRACK(9, "Level 2 transition information"),
        DEF_PACKET_TO_TRACK(10, "Safe consist length information for Supervised Manoeuvre"),
        DEF_PACKET_TO_TRACK(11, "Validated train data"),
        DEF_PACKET_TO_TRACK(12, "Default train data for Supervised Manoeuvre"),
        DEF_PACKET_TO_TRACK(44, "Data used by applications outside the ERTMS/ETCS system"),
};

static etcs_packet_t *etcs_packets_to_track[256];

static void init_packet_info() {
        initialize_packets(etcs_packets_to_train_raw, array_length(etcs_packets_to_train_raw), etcs_packets_to_train);
        initialize_packets(etcs_packets_to_track_raw, array_length(etcs_packets_to_track_raw), etcs_packets_to_track);
}

static void initialize_packets(etcs_packet_t packets[], const size_t size, etcs_packet_t *lookup[]) {
        for (size_t i = 0; i < 256; i++) {
                lookup[i] = NULL;
        }
        for (size_t i = 0; i < size; i++) {
                const uint8_t nid_packet = packets[i].nid_packet;
                lookup[nid_packet] = &packets[i];
        }
}

static etcs_packet_t etcs_unknown_packet_to_train = {
        0, // dummy value
        "Unknown packet",
        0,
        0,
        "etcs.track_to_train.unknown_packet",
        NULL
};

static etcs_packet_t etcs_unknown_packet_to_track = {
        0, // dummy value
        "Unknown packet",
        0,
        0,
        "etcs.train_to_track.unknown_packet",
        NULL
};
