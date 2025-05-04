package dev.kosztadani.etcs_wireshark.mdb_to_pcapng;

/**
 * Entry point to the application.
 */
public final class MdbToPcapngMain {

    private final String[] args;

    private MdbToPcapngMain(final String[] args) {
        this.args = args;
    }

    /**
     * The main method of the application.
     *
     * @param args The command-line arguments passed to the application
     */
    public static void main(final String[] args) {
        new MdbToPcapngMain(args).run();
    }

    private void run() {
    }
}
