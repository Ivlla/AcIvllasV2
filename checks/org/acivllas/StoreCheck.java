package org.acivllas;

import java.nio.file.*;
import java.util.*;

public final class StoreCheck {
    public static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]).resolve("bans.properties");
        var store = new BanStore(file);
        UUID a = UUID.randomUUID(), b = UUID.randomUUID(), installation = UUID.randomUUID();
        String device = store.token(installation);
        require(device.matches("[0-9a-f]{64}"));
        require(!new BanStore(file.resolveSibling("other.properties")).token(installation).equals(device));
        store.banAccount(a, "Alice", "Использование KillAura");
        require(!store.deviceBanned(device));
        store.banInstallation(b, "Bob", device);
        require(store.reason(b) == null);
        store = new BanStore(file);
        require(store.token(installation).equals(device) && store.deviceBanned(device));
        require("Использование KillAura".equals(store.reason(a)));
        store.banInstallation(a, "Alice", device);
        require(store.pardonDevice("aLiCe") && store.deviceBanned(device));
        require(!store.pardonDevice(device.substring(0,20)));
        require(store.pardonDevice(device) && !store.deviceBanned(device));
        require(store.reason(a) != null && store.pardonAccount(a));
        require(new BanStore(file).reason(a) == null);
        UUID c = UUID.randomUUID(), c2 = UUID.randomUUID();
        store.banAccount(c, "Cheater", "KillAura");
        require("KillAura".equals(store.reason(c2, "cHeAtEr", true)));
        require(store.reason(c2, "cHeAtEr", false) == null);
        require(new BanStore(file).reason(c2, "CHEATER", true) != null);
        require(store.pardonAccount(c) && store.reason(c2, "cheater", true) == null);
        var log = new DeviceLog(file.resolveSibling("devices.properties"));
        UUID acc = UUID.randomUUID();
        require(log.observe(acc, "aaa", 100, 90) == null);
        require(log.observe(acc, "aaa", 101, 90) == null);
        require("aaa".equals(log.observe(acc, "bbb", 102, 90)));
        require(log.observe(acc, "bbb", 103, 90) == null);
        require(log.observe(UUID.randomUUID(), "ccc", 300, 90) == null);
        require(log.observe(acc, "ddd", 300, 90) == null); // old entry expired and was purged
        System.out.println("StoreCheck OK");
    }
    static void require(boolean ok) { if (!ok) throw new AssertionError(); }
}
