package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

final class EtcsMessageTest {

    private static final int BUFFER_SIZE = 8;

    private final ByteBuffer buffer = ByteBuffer.allocate(BUFFER_SIZE);


    @Test
    void testEmpty() {
        EtcsMessage message = new EtcsMessage(Collections.emptyList());
        message.writeToBuffer(buffer);
        buffer.flip();
        assertFalse(buffer.hasRemaining());
    }

    @Test
    void testWithoutPadding() {
        EtcsMessage message = new EtcsMessage(List.of(
            EtcsVariable.fromBinaryString(8, "1100 0011"),
            EtcsVariable.fromBinaryString(8, "1100 0011")
        ));
        message.writeToBuffer(buffer);
        buffer.flip();
        assertEquals((byte) 0b1100_0011, buffer.get());
        assertEquals((byte) 0b1100_0011, buffer.get());
        assertFalse(buffer.hasRemaining());
    }

    @Test
    void testWithPadding() {
        EtcsMessage message = new EtcsMessage(List.of(
            EtcsVariable.fromBinaryString(5, "0 0011"),
            EtcsVariable.fromBinaryString(5, "0 0011")
        ));
        message.writeToBuffer(buffer);
        buffer.flip();
        assertEquals((byte) 0b000_11000, buffer.get());
        assertEquals((byte) 0b110_00000, buffer.get());
        assertFalse(buffer.hasRemaining());
    }
}
