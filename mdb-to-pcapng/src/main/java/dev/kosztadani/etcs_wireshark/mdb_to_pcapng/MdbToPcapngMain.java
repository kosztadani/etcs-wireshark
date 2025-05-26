package dev.kosztadani.etcs_wireshark.mdb_to_pcapng;

import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb.MdbMessage;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb.MdbReader;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb.MessageInterface;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.pcapng.NameResolutionEntry;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.pcapng.PcapngWriter;
import dev.kosztadani.etcs_wireshark.mdb_to_pcapng.pcapng.UdpPacket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

/**
 * Entry point to the application.
 */
public final class MdbToPcapngMain {

    private static final InetSocketAddress TRAIN_ADDRESS = new InetSocketAddress("192.0.2.10", 50010);

    private static final InetSocketAddress EUROLOOP_ADDRESS = new InetSocketAddress("192.0.2.20", 50020);

    private static final InetSocketAddress EUROBALISE_ADDRESS = new InetSocketAddress("192.0.2.30", 50030);

    private static final InetSocketAddress EURORADIO_ADDRESS = new InetSocketAddress("192.0.2.40", 50040);

    private static final List<NameResolutionEntry> NAMES = List.of(
        new NameResolutionEntry(TRAIN_ADDRESS.getAddress(), "TRAIN"),
        new NameResolutionEntry(EUROLOOP_ADDRESS.getAddress(), "EUROLOOP"),
        new NameResolutionEntry(EUROBALISE_ADDRESS.getAddress(), "EUROBALISE"),
        new NameResolutionEntry(EURORADIO_ADDRESS.getAddress(), "EURORADIO")
    );

    private final String[] args;

    private MdbToPcapngMain(final String[] args) {
        this.args = args;
    }

    /**
     * The main method of the application.
     *
     * @param args The command-line arguments passed to the application.
     * @throws IOException if an I/O error occurs.
     */
    public static void main(final String[] args) throws Exception {
        new MdbToPcapngMain(args).run();
    }

    private void run() throws IOException {
        if (args.length == 0) {
            System.out.println("Usage: mdb-to-pcapng <path>...");
        } else {
            for (String input : args) {
                processPath(Path.of(input));
            }
        }
    }

    private void processPath(final Path path) throws IOException {
        if (Files.isDirectory(path)) {
            processDirectory(path);
        } else if (Files.exists(path)) {
            processFile(path);
        } else {
            System.out.println("WARNING: ignored input: " + path);
        }
    }

    private void processDirectory(final Path directory) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            List<Path> list = files
                .filter(p -> p.getFileName().toString().endsWith(".mdb"))
                .toList();
            if (list.isEmpty()) {
                System.out.println("WARNING: empty directory: " + directory);
            }
            for (Path file : list) {
                processFile(file);
            }
        }
    }

    @SuppressWarnings("checkstyle:MagicNumber")
    private void processFile(final Path inputFile) throws IOException {
        Path directory = inputFile.getParent();
        String inputName = inputFile.getFileName().toString();
        String outputName = inputName.substring(0, inputName.length() - 3) + "pcapng";
        Path outputFile = directory.resolve(outputName);
        List<MdbMessage> messages = read(inputFile);
        if (!messages.isEmpty()) {
            write(messages, outputFile);
        }
    }

    private List<MdbMessage> read(final Path inputFile) {
        try (MdbReader reader = new MdbReader(inputFile)) {
            return reader.read();
        } catch (Throwable e) {
            System.err.println("ERROR reading file: " + inputFile);
            e.printStackTrace();
            return Collections.emptyList();
        }
    }

    private void write(final List<MdbMessage> messages, final Path outputFile) throws IOException {
        try (PcapngWriter writer = new PcapngWriter(outputFile)) {
            writer.writeNameResolution(NAMES);
            int sequence = 0;
            for (MdbMessage message : messages) {
                UdpPacket udpPacket = new UdpPacket(
                    sender(message),
                    receiver(message),
                    sequence++,
                    message.message()
                );
                writer.writeData(udpPacket, message.comment());
            }
        }
    }

    private InetSocketAddress sender(final MdbMessage message) {
        return switch (message.direction()) {
            case IN -> partnerAddress(message.messageInterface());
            case OUT -> TRAIN_ADDRESS;
        };
    }

    private InetSocketAddress receiver(final MdbMessage message) {
        return switch (message.direction()) {
            case IN -> TRAIN_ADDRESS;
            case OUT -> partnerAddress(message.messageInterface());
        };
    }

    private InetSocketAddress partnerAddress(final MessageInterface messageInterface) {
        return switch (messageInterface) {
            case LTM -> EUROLOOP_ADDRESS;
            case BTM -> EUROBALISE_ADDRESS;
            case RTM -> EURORADIO_ADDRESS;
        };
    }
}
