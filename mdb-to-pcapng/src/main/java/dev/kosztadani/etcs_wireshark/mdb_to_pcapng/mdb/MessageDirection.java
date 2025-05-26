package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.mdb;

/**
 * The direction of a message.
 */
public enum MessageDirection {
    /**
     * Message incoming to the train.
     */
    IN("I"),
    /**
     * Message outgoing from the train.
     */
    OUT("O");

    private final String text;

    MessageDirection(final String text) {
        this.text = text;
    }

    /**
     * Parses the letter "I" or "O" into a message direction.
     *
     * @param input The letter "I" or "O".
     * @return The message direction.
     * @throws IllegalArgumentException if the input is not "I" or "O".
     */
    public static MessageDirection fromString(final String input) {
        for (MessageDirection value : values()) {
            if (value.text.equals(input)) {
                return value;
            }
        }
        throw new IllegalArgumentException("Not supported: " + input);
    }
}
