package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb;

import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.EtcsMessage;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.EtcsVariable;

/**
 * Represents a message read from an MDB file.
 *
 * @param messageInterface The interface on which the train processed the message.
 * @param direction        The direction of the message, from the train's perspective.
 * @param message          The message (a sequence of {@link EtcsVariable}s).
 * @param comment          A comment that identifies this message.
 */
public record MdbMessage(
    MessageInterface messageInterface,
    MessageDirection direction,
    EtcsMessage message,
    String comment) {

}
