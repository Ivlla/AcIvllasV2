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
        Session session = new Session();
        UUID installation = UUID.randomUUID();
        require(!session.beginReprobe(10, 15));
        require(!session.matchesIdentity("device", Session.EMPTY_ID));
        require(session.matchesIdentity("device", installation));
        session.accept("device", installation, 20, 15);
        require(session.matchesIdentity("device", installation));
        require(!session.matchesIdentity("different", installation));
        require(!session.matchesIdentity("device", UUID.randomUUID()));
        require(!session.beginReprobe(34, 15));
        require(session.beginReprobe(35, 15));
        require(!session.beginReprobe(55, 15)); // network ticket consumed, main-thread inspection still queued
        session.accept("device", installation, 60, 15);
        require(!session.beginReprobe(74, 15));
        require(!session.beginReprobe(75, 0));
        require(session.beginReprobe(75, 15));
        System.out.println("TicketCheck OK");
    }
    static void require(boolean ok) { if (!ok) throw new AssertionError(); }
}
