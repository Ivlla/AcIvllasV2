package org.acivllas;

import java.util.UUID;

public final class HardwareCheck {
    public static void main(String[] args) {
        var first = HardwareIdentity.fingerprint("vendor|model|serial-123");
        if (!first.equals(HardwareIdentity.fingerprint("vendor|model|serial-123")))
            throw new AssertionError("Hardware identity changed");
        if (first.equals(HardwareIdentity.fingerprint("vendor|model|serial-456")))
            throw new AssertionError("Different devices matched");

        for (String invalid : new String[]{"", "unknown", "default string", "00000000",
                "ffffffff", "00000000-0000-0000-0000-000000000000",
                "To be filled by O.E.M.", "System Serial Number", "N/A"})
            if (HardwareIdentity.valid(invalid)) throw new AssertionError("Accepted placeholder: " + invalid);
        if (!HardwareIdentity.valid("abc12345")) throw new AssertionError("Rejected serial");

        UUID installA = UUID.fromString("11111111-2222-3333-4444-555555555555");
        UUID installB = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        UUID fallbackA = HardwareIdentity.installationFallback(installA);
        if (!fallbackA.equals(HardwareIdentity.installationFallback(installA)))
            throw new AssertionError("Installation fallback changed");
        if (fallbackA.equals(HardwareIdentity.installationFallback(installB)))
            throw new AssertionError("Different installations matched");
        if (HardwareIdentity.installationFallback(HardwareIdentity.UNAVAILABLE)
                .equals(HardwareIdentity.UNAVAILABLE) == false)
            throw new AssertionError("Missing installation ID must remain unavailable");

        System.out.println("HardwareCheck OK");
    }
}
