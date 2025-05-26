package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common;

import java.math.BigInteger;

/**
 * A numerical value and its size in bits.
 *
 * @param size  The size of the variable in bits.
 * @param value The value of the variable.
 */
public record EtcsVariable(int size, BigInteger value) {

    /**
     * Creates a variable from a size and a value.
     *
     * @param size  The size of the variable in bits.
     * @param value The value of the variable.
     * @throws EtcsVariableException if the value is negative or doesn't fit in the specified number of bits.
     */
    public EtcsVariable {
        if (value.compareTo(BigInteger.ZERO) < 0) {
            throw new EtcsVariableException("Value is negative.");
        }
        BigInteger limit = BigInteger.ONE.shiftLeft(size);
        if (value.compareTo(limit) >= 0) {
            throw new EtcsVariableException("Value can doesn't fit into the specified number of bits.");
        }
    }

    /**
     * Parses a single ASCII character.
     *
     * @param value The ASCII character.
     * @return An 8-bit variable from the character.
     * @throws EtcsVariableException if the character is not a single byte.
     */
    @SuppressWarnings("checkstyle:MagicNumber")
    public static EtcsVariable fromCharacter(final char value) {
        if ((value & 0xFF00) != 0) {
            throw new EtcsVariableException("Character is not a single byte.");
        }
        return new EtcsVariable(Byte.SIZE, BigInteger.valueOf(value & 0xFF));
    }

    /**
     * Parses a decimal string representation.
     *
     * @param size  The size of the variable in bits.
     * @param value The decimal string representation.
     * @return A variable from the parsed decimal.
     * @throws EtcsVariableException if the string does not represent a valid variable.
     */
    @SuppressWarnings("checkstyle:MagicNumber")
    public static EtcsVariable fromDecimalString(final int size, final String value) {
        return fromString(size, value, 10);
    }

    /**
     * Parses a binary string representation.
     *
     * @param size  The size of the variable in bits.
     * @param value The binary string representation.
     * @return A variable from the parsed binary string.
     * @throws EtcsVariableException if the string does not represent a valid variable.
     */
    public static EtcsVariable fromBinaryString(final int size, final String value) {
        return fromString(size, value, 2);
    }

    /**
     * Parses a hexadecimal string representation.
     *
     * @param size  The size of the variable in bits.
     * @param value The hexadecimal string representation.
     * @return A variable from the parsed hexadecimal string.
     * @throws EtcsVariableException if the string does not represent a valid variable.
     */
    @SuppressWarnings("checkstyle:MagicNumber")
    public static EtcsVariable fromHexString(final int size, final String value) {
        return fromString(size, value, 16);
    }

    private static EtcsVariable fromString(final int size, final String value, final int radix) {
        String stripped = removeSpaces(value);
        try {
            BigInteger number = new BigInteger(stripped, radix);
            return new EtcsVariable(size, number);
        } catch (NumberFormatException e) {
            throw new EtcsVariableException("Invalid number format:\"" + value + "\"", e);
        }
    }

    private static String removeSpaces(final String value) {
        return value.replaceAll("\\s+", "");
    }
}
