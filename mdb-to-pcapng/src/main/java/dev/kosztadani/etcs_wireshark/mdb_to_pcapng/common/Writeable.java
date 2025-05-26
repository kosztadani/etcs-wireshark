package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * An object that can be written into a {@link ByteBuffer}.
 */
public interface Writeable {

    /**
     * Write the object into a {@link ByteBuffer}.
     *
     * <p>
     * Implementations are allowed change the {@link ByteOrder} of the buffer.
     * Callers should not make assumptions about the byte order of the buffer
     * after having called this method.
     *
     * @param buffer The buffer to use.
     */
    void writeToBuffer(ByteBuffer buffer);
}
