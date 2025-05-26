package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * A sequence of {@link EtcsVariable}s.
 *
 * @param variables The list of variables.
 */
public record EtcsMessage(List<EtcsVariable> variables)
    implements Writeable {

    @Override
    public void writeToBuffer(final ByteBuffer buffer) {
        int totalLength = 0;
        // start with 1, so that leading zeros are not lost
        BigInteger value = BigInteger.ONE;
        for (EtcsVariable variable : variables) {
            totalLength += variable.size();
            value = value.shiftLeft(variable.size());
            value = value.or(variable.value());
        }
        value = value.shiftLeft(padding(totalLength));
        byte[] bytes = value.toByteArray();
        // ignore the leading byte
        buffer.put(bytes, 1, bytes.length - 1);
    }

    private int padding(final int length) {
        return (Byte.SIZE - (length % Byte.SIZE)) % Byte.SIZE;
    }
}
