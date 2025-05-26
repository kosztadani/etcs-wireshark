package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.common;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class EtcsVariableTest {

    @Test
    void testConstruction() {
        EtcsVariable variable = new EtcsVariable(5, BigInteger.valueOf(10));
        assertEquals(5, variable.size());
        assertEquals(BigInteger.valueOf(10), variable.value());
    }

    @Test
    void testNegative() {
        BigInteger value = BigInteger.valueOf(-10);
        assertThrows(EtcsVariableException.class, () ->
            new EtcsVariable(5, value)
        );
    }

    @Test
    void testTooLarge() {
        BigInteger value = BigInteger.valueOf(100);
        assertThrows(EtcsVariableException.class, () ->
            new EtcsVariable(5, value)
        );
    }

    @Test
    void testCharacter() {
        EtcsVariable variable = EtcsVariable.fromCharacter(' ');
        assertEquals(8, variable.size());
        assertEquals(BigInteger.valueOf(' '), variable.value());
    }

    @Test
    void testCharacterOutOfRange() {
        assertThrows(EtcsVariableException.class, () ->
            EtcsVariable.fromCharacter('ő')
        );
    }

    @Test
    void testDecimal() {
        EtcsVariable variable = EtcsVariable.fromDecimalString(10, "64");
        assertEquals(10, variable.size());
        assertEquals(BigInteger.valueOf(64), variable.value());
    }

    @Test
    void testDecimalOutOfRange() {
        assertThrows(EtcsVariableException.class, () ->
            EtcsVariable.fromDecimalString(5, "64")
        );
    }

    @Test
    void testDecimalIsNegative() {
        assertThrows(EtcsVariableException.class, () ->
            EtcsVariable.fromDecimalString(5, "-10")
        );
    }

    @Test
    void testBinary() {
        EtcsVariable variable = EtcsVariable.fromBinaryString(7, "001 0001");
        assertEquals(7, variable.size());
        assertEquals(BigInteger.valueOf(0b001_0001), variable.value());
    }

    @Test
    void testBinaryPadding() {
        EtcsVariable variable = EtcsVariable.fromBinaryString(8, "001 0001");
        assertEquals(8, variable.size());
        assertEquals(BigInteger.valueOf(0b001_0001), variable.value());
    }

    @Test
    void testBinaryOutOfRange() {
        assertThrows(EtcsVariableException.class, () ->
            EtcsVariable.fromBinaryString(5, "111111")
        );
    }

    @Test
    void testBinaryInvalid() {
        assertThrows(EtcsVariableException.class, () ->
            EtcsVariable.fromBinaryString(5, "12")
        );
    }

    @Test
    void testHexadecimal() {
        EtcsVariable variable = EtcsVariable.fromHexString(16, "FA");
        assertEquals(16, variable.size());
        assertEquals(BigInteger.valueOf(0xFA), variable.value());
    }

    @Test
    void testHexadecimalPadding() {
        EtcsVariable variable = EtcsVariable.fromHexString(16, "F");
        assertEquals(16, variable.size());
        assertEquals(BigInteger.valueOf(0xF), variable.value());
    }

    @Test
    void testHexadecimalInvalid() {
        assertThrows(EtcsVariableException.class, () ->
            EtcsVariable.fromHexString(64, "twelve")
        );
    }
}
