package org.acivllas;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/** Only the server thread changes this state. The network thread consumes tickets independently. */
final class Session {
    static final UUID EMPTY_ID = new UUID(0, 0);
    String token;
    private UUID installation;
    String state = "ожидание отчета";
    int weakStreak;
    final Set<String> signals = new LinkedHashSet<>();
    private boolean awaitingReply = true;
    private long nextProbe;

    boolean matchesIdentity(String candidate, UUID install) {
        return !EMPTY_ID.equals(install) && (token == null || (token.equals(candidate) && installation.equals(install)));
    }

    void accept(String candidate, UUID install, long now, long interval) {
        token = candidate;
        installation = install;
        state = "отчет принят";
        awaitingReply = false;
        nextProbe = now + interval;
    }

    boolean beginReprobe(long now, long interval) {
        if (interval <= 0 || awaitingReply || now - nextProbe < 0) return false;
        awaitingReply = true;
        return true;
    }
}
