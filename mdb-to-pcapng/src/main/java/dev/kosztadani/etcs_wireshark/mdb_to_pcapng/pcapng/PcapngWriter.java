package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.pcapng;

import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common.Writeable;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collection;

/**
 * Utility to create and write PCAPNG files.
 */
public final class PcapngWriter
    implements Closeable {

    private static final int BUFFER_SIZE = 128 * 1024;

    private static final int PCAPNG_PADDING_SIZE = 4; // bytes

    private final SeekableByteChannel output;

    private final ByteBuffer buffer = ByteBuffer
        .allocate(BUFFER_SIZE)
        .order(ByteOrder.LITTLE_ENDIAN);

    /**
     * Creates a new PCAPNG writer.
     *
     * @param outputFile The path of the resulting (or overwritten) file.
     * @throws IOException if an I/O error occurs.
     */
    public PcapngWriter(final Path outputFile) throws IOException {
        output = Files.newByteChannel(outputFile,
            StandardOpenOption.WRITE,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING);
        initialize();
    }

    private void initialize() throws IOException {
        writeSectionHeader();
        writeInterfaceDescription();
        flush();
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    private void writeSectionHeader() {
        int blockLength = 28;
        buffer
            .putInt(0x0A0D0D0A) // block type
            .putInt(blockLength)
            // body
            .putInt(0x1A2B3C4D) // byte-order magic
            .putShort((short) 1) // major version
            .putShort((short) 0) // minor version
            .putLong(0) // section size
            // no options
            // no padding
            // end body
            .putInt(blockLength);
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    private void writeInterfaceDescription() {
        int blockLength = 20;
        buffer
            .putInt(0x00000001) // block type
            .putInt(blockLength)
            .putShort((short) 228) // LINKTYPE_IPV4
            .putShort((short) 0) // reserved
            .putInt(0) // SnapLen: no limit
            // no options
            .putInt(blockLength);
    }

    /**
     * Writes a name resolution block to the PCAPNG file.
     *
     * @param nameResolutions The entries to write.
     */
    @SuppressWarnings("checkstyle:MagicNumber")
    public void writeNameResolution(final Collection<NameResolutionEntry> nameResolutions) {
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int initialPosition = buffer.position();
        int blockLengthPosition = initialPosition + 4;
        buffer
            .putInt(0x00000004) // block type
            .putInt(0); // PLACEHOLDER: block size
        // nrb_record_ipv4 for each entry
        for (NameResolutionEntry nameResolutionEntry : nameResolutions) {
            byte[] address = nameResolutionEntry.address().getAddress();
            byte[] name = nameResolutionEntry.name().getBytes(StandardCharsets.UTF_8);
            int size = address.length + name.length + 1;
            buffer
                .putShort((short) 0x0001) // IPv4
                .putShort((short) size) // record value size
                .put(address)
                .put(name)
                .put((byte) 0x00)
                .put(new byte[padding(size)]);
        }
        // nrb_record_end
        buffer
            .putShort((short) 0x0000) // end
            .putShort((short) 0); // record value size
        int blockLength = buffer.position() - initialPosition + 4;
        buffer.putInt(blockLength);
        buffer.putInt(blockLengthPosition, blockLength);
    }

    /**
     * Writes a packet to the PCAPNG file.
     *
     * @param packet The data in the packet.
     * @throws IOException if an I/O error occurs.
     */
    public void writeData(final Writeable packet) throws IOException {
        writeData(packet, null);
    }

    /**
     * Writes a packet to the PCAPNG file.
     *
     * @param packet  The data in the packet.
     * @param comment A comment associated with the packet. Can be null.
     * @throws IOException if an I/O error occurs.
     */
    @SuppressWarnings("checkstyle:MagicNumber")
    public void writeData(final Writeable packet, final String comment) throws IOException {
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int initialPosition = buffer.position();
        int blockLengthPosition = initialPosition + 4;
        int packetLengthPosition = initialPosition + 20;
        buffer
            .putInt(0x00000006) // block type
            .putInt(0) // PLACEHOLDER: block size
            .putInt(0) // interface ID
            .putInt(0) // timestamp upper 32 bits
            .putInt(0) // timestamp lower 32 bits
            .putInt(0) // PLACEHOLDER: captured packet size
            .putInt(0); // PLACEHOLDER: original packet size
        int positionBeforePacket = buffer.position();
        packet.writeToBuffer(buffer);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int packetLength = buffer.position() - positionBeforePacket;
        int padding = padding(packetLength);
        buffer.put(new byte[padding]);
        if (comment != null) {
            writeCommentBlock(comment);
        }
        int blockLength = buffer.position() - initialPosition + 4;
        buffer.putInt(blockLength);
        buffer.putInt(blockLengthPosition, blockLength);
        buffer.putInt(packetLengthPosition, packetLength);
        buffer.putInt(packetLengthPosition + 4, packetLength);
        flush();
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    private void writeCommentBlock(final String comment) {
        byte[] commentBytes = comment.getBytes(StandardCharsets.UTF_8);
        int optionPadding = padding(commentBytes.length);
        int optionLength = 4 + commentBytes.length + optionPadding;
        buffer
            .putShort((short) 1) // option type: opt_comment
            .putShort((short) optionLength)
            .put(commentBytes)
            .put(new byte[optionPadding])
            .putShort((short) 0) // option type: opt_endofopt
            .putShort((short) 0); // option size
    }

    private int padding(final int length) {
        return (PCAPNG_PADDING_SIZE - (length % PCAPNG_PADDING_SIZE)) % PCAPNG_PADDING_SIZE;
    }

    private void flush() throws IOException {
        buffer.flip();
        output.write(buffer);
        buffer.compact();
    }

    /**
     * Closes the PCAPNG file after flushing any remaining data to be written.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        flush();
        output.close();
    }
}
