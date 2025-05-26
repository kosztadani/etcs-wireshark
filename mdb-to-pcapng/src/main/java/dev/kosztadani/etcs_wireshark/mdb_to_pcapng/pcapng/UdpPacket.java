package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.pcapng;

import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.Writeable;

import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A UDP packet over IPv4.
 *
 * @param from     The source address.
 * @param to       The destination address.
 * @param sequence The sequence number.
 * @param payload  The payload in the packet.
 */
public record UdpPacket(InetSocketAddress from, InetSocketAddress to, int sequence, Writeable payload)
    implements Writeable {

    /**
     * Creates a new UDP packet.
     *
     * @param from     The source address.
     * @param to       The destination address.
     * @param sequence The sequence number.
     * @param payload  The payload in the packet.
     * @throws IllegalArgumentException if an address is not an IPv4 address.
     */
    public UdpPacket {
        checkAddress(from);
        checkAddress(to);
    }

    private void checkAddress(final InetSocketAddress address) {
        if (!(address.getAddress() instanceof Inet4Address)) {
            throw new IllegalArgumentException("Only IPv4 addresses are supported");
        }
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    @Override
    public void writeToBuffer(final ByteBuffer buffer) {
        buffer.order(ByteOrder.BIG_ENDIAN);
        int startPosition = buffer.position();
        int ipLengthPosition = startPosition + 2;
        int udpLengthPosition = startPosition + 24;
        buffer
            // IPv4
            .put((byte) 0x45) // IPv4; header size: 5 * 4 bytes
            .put((byte) 0x00) // differentiated services
            .putShort((short) 0) // PLACEHOLDER: total size
            .putShort((short) sequence) // identification
            .putShort((short) 0x4000) // don't fragment, fragment offset 0
            .put((byte) 0x40) // time to live
            .put((byte) 0x11) // protocol: UDP
            .putShort((short) 0x0000) // header checksum
            .put(from.getAddress().getAddress())
            .put(to.getAddress().getAddress())
            // UDP
            .putShort((short) from.getPort())
            .putShort((short) to.getPort())
            .putShort((short) 0) // PLACEHOLDER: UDP size
            .putShort((short) 0); // checksum
        int payloadStartPosition = buffer.position();
        payload.writeToBuffer(buffer);
        buffer.order(ByteOrder.BIG_ENDIAN);
        int payloadLength = buffer.position() - payloadStartPosition;
        int udpLength = payloadLength + 8;
        int ipLength = udpLength + 20;
        buffer.putShort(ipLengthPosition, (short) ipLength);
        buffer.putShort(udpLengthPosition, (short) udpLength);
    }
}
