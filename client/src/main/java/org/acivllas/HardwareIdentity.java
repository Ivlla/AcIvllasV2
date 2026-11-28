package org.acivllas;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import oshi.SystemInfo;

/**
 * Stable, privacy-preserving device identifier.
 *
 * The original motherboard-serial fingerprint is kept byte-for-byte compatible
 * so existing hardware bans continue to match. If firmware does not expose a
 * usable board serial, other OSHI identifiers are tried. The installation ID
 * is the final availability fallback; it is stable for this installation but
 * is not a machine-wide hardware identifier.
 */
final class HardwareIdentity {
    static final UUID UNAVAILABLE = new UUID(0, 0);
    private static final Set<String> INVALID = Set.of("", "unknown", "none", "null",
            "default string", "to be filled by o.e.m.", "to be filled by oem",
            "system serial number", "not specified", "not applicable", "n/a",
            "not available", "not set", "invalid", "undefined", "00000000",
            "ffffffff", "12345678");

    private HardwareIdentity() {}

    static UUID read(UUID installation) {
        try {
            var computer = new SystemInfo().getHardware().getComputerSystem();
            var board = computer.getBaseboard();

            // Keep the v1 input exactly unchanged for compatibility with existing bans.
            String boardSerial = normalize(board.getSerialNumber());
            if (valid(boardSerial)) {
                String identity = "acivllas:motherboard:v1|" + normalize(board.getManufacturer())
                        + "|" + normalize(board.getModel()) + "|" + boardSerial;
                return fingerprint(identity);
            }

            // Some OEM firmware hides the baseboard serial but exposes a system UUID.
            String hardwareUuid = normalize(computer.getHardwareUUID());
            if (valid(hardwareUuid))
                return fingerprint("acivllas:hardware-uuid:v1|" + hardwareUuid);

            // Last hardware-based option: a chassis/system or firmware serial.
            String systemSerial = normalize(computer.getSerialNumber());
            String firmwareSerial = normalize(computer.getFirmware().getSerialNumber());
            if (valid(systemSerial) || valid(firmwareSerial)) {
                String identity = "acivllas:system-serial:v1|" + systemSerial + "|"
                        + firmwareSerial + "|" + normalize(board.getManufacturer())
                        + "|" + normalize(board.getModel());
                return fingerprint(identity);
            }
        } catch (RuntimeException | LinkageError unavailable) {
            // OSHI or the platform firmware provider is unavailable; use the stable install fallback below.
        }
        return installationFallback(installation);
    }

    static boolean valid(String serial) {
        if (serial == null) return false;
        String value = normalize(serial);
        if (INVALID.contains(value) || value.matches("[0f -]+")) return false;
        String compact = value.replaceAll("[^a-z0-9]", "");
        return !compact.isEmpty() && !compact.matches("0+") && !compact.matches("f+");
    }

    static UUID installationFallback(UUID installation) {
        if (installation == null || UNAVAILABLE.equals(installation)) return UNAVAILABLE;
        return fingerprint("acivllas:installation-fallback:v1|" + installation);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.strip().toLowerCase(Locale.ROOT);
    }

    static UUID fingerprint(String identity) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(identity.getBytes(StandardCharsets.UTF_8));
            ByteBuffer bytes = ByteBuffer.wrap(hash);
            return new UUID(bytes.getLong(), bytes.getLong());
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
