package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb;

/**
 * The messaging interface on which the train received or sent a message.
 */
public enum MessageInterface {
    /**
     * Loop Transmission Module.
     */
    LTM,
    /**
     * Balise Transmission Module.
     */
    BTM,
    /**
     * Radio Transmission Module.
     */
    RTM
}
