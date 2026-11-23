package org.acivllas;

import java.util.UUID;
import java.util.stream.IntStream;

public final class TicketCheck {
    public static void main(String[] args) {
        Tickets<String> tickets = new Tickets<>();
        UUID nonce = tickets.issue("first", 10);
        require(!tickets.accept("second", nonce, 20));
        require(!tickets.accept("first", UUID.randomUUID(), 20));
        long accepted = IntStream.range(0, 128).parallel()
                .filter(i -> tickets.accept("first", nonce, 20)).count();
        require(accepted == 1);
        UUID old = tickets.issue("first", 50);
        UUID current = tickets.issue("first", 70);
        require(!tickets.accept("first", old, 75));
        require(!tickets.expire("first", 70 + Tickets.TTL));
        require(!tickets.accept("first", current, 71 + Tickets.TTL));
        require(tickets.expire("first", 71 + Tickets.TTL));
        require(!tickets.expire("first", 72 + Tickets.TTL));
        System.out.println("TicketCheck OK");
    }
    static void require(boolean ok) { if (!ok) throw new AssertionError(); }
}
