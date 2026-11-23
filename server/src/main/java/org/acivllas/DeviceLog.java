package org.acivllas;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Account to device-token history with retention. Tokens are server-side HMACs; no raw identifiers are stored. */
final class DeviceLog {
    private final Path file;
    private Properties rows = new Properties();
    DeviceLog(Path file) throws IOException {
        this.file = file;
        Files.createDirectories(file.getParent());
        if (Files.exists(file)) try (var in = Files.newInputStream(file)) { rows.load(in); }
    }
    /** Records the token for the account. Returns the previous token if it differs, otherwise null. */
    String observe(UUID account, String token, long day, int retentionDays) throws IOException {
        Properties next = (Properties) rows.clone();
        next.stringPropertyNames().stream().filter(k -> expired(next.getProperty(k), day, retentionDays))
                .toList().forEach(next::remove);
        String old = next.getProperty(account.toString());
        String previous = null;
        if (old != null && old.indexOf('|') > 0) {
            String t = old.substring(0, old.indexOf('|'));
            if (!t.equals(token)) previous = t;
        }
        next.setProperty(account.toString(), token + "|" + day);
        if (!next.equals(rows)) commit(next);
        return previous;
    }
    private static boolean expired(String value, long day, int retentionDays) {
        try { return day - Long.parseLong(value.substring(value.indexOf('|') + 1)) > retentionDays; }
        catch (RuntimeException malformed) { return true; }
    }
    private void commit(Properties next) throws IOException {
        Path temp = Files.createTempFile(file.getParent(), "dev-", ".tmp");
        try {
            try (var out = Files.newOutputStream(temp)) { next.store(out, "AcIvllas device history"); }
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            rows = next;
        } finally { Files.deleteIfExists(temp); }
    }
}
