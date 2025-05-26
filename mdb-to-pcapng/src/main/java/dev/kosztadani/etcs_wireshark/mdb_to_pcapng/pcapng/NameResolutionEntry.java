package dev.kosztadani.etcs_wireshark.mdb_to_pcapng.pcapng;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * An IPv4 address associated with a name.
 *
 * @param address The IPv4 address
 * @param name    The name associated with the address.
 */
public record NameResolutionEntry(InetAddress address, String name) {

    /**
     * Creates a new name resolution entry.
     *
     * @param address The IPv4 address
     * @param name    The name associated with the address.
     * @throws IllegalArgumentException if the address is not an IPv4 address.
     */
    public NameResolutionEntry {
        if (!(address instanceof Inet4Address)) {
            throw new IllegalArgumentException("Only IPv4 addresses are supported");
        }
    }
}
