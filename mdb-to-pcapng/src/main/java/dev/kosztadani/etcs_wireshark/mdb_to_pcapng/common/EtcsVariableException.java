package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common;

import java.io.Serial;

/**
 * Thrown when parsing or instantiating an {@link EtcsVariable} fails.
 */
public final class EtcsVariableException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 3182771937961112967L;

    /**
     * Constructs a new exception with the specified detail message.
     *
     * @param message The detail message.
     */
    public EtcsVariableException(final String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified cause and detail message.
     *
     * @param message The detail message.
     * @param cause   The cause.
     */
    public EtcsVariableException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
