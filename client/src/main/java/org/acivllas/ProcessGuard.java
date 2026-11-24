package org.acivllas;

import com.mojang.logging.LogUtils;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * Windows only. Denies other processes the rights needed to inject code into this one:
 * create a thread, perform virtual-memory operations and writes, duplicate handles, change the DACL or owner.
 * Everything else (query, read, terminate, synchronize) stays allowed. A process holding SeDebugPrivilege
 * (running as administrator) or a kernel driver is not stopped by this.
 */
final class ProcessGuard {
    private ProcessGuard() {}
    public interface Advapi extends Library {
        Advapi INSTANCE = Native.load("advapi32", Advapi.class);
        boolean ConvertStringSecurityDescriptorToSecurityDescriptorW(WString sddl, int revision,
                PointerByReference descriptor, IntByReference size);
        boolean GetSecurityDescriptorDacl(Pointer descriptor, IntByReference present,
                PointerByReference dacl, IntByReference defaulted);
        int SetSecurityInfo(Pointer handle, int objectType, int information,
                Pointer owner, Pointer group, Pointer dacl, Pointer sacl);
    }
    // Everyone: deny CREATE_THREAD|VM_OPERATION|VM_WRITE|DUP_HANDLE|WRITE_DAC|WRITE_OWNER, allow the rest.
    private static final String SDDL = "D:(D;;0xC006A;;;WD)(A;;0x1FFFFF;;;WD)";
    private static Boolean last;

    static synchronized boolean harden() {
        if (!Platform.isWindows()) return false;
        boolean ok = false;
        try {
            var descriptor = new PointerByReference();
            if (Advapi.INSTANCE.ConvertStringSecurityDescriptorToSecurityDescriptorW(new WString(SDDL), 1, descriptor, null)) {
                try {
                    var present = new IntByReference();
                    var dacl = new PointerByReference();
                    var defaulted = new IntByReference();
                    if (Advapi.INSTANCE.GetSecurityDescriptorDacl(descriptor.getValue(), present, dacl, defaulted)
                            && present.getValue() != 0) {
                        Pointer self = Kernel32.INSTANCE.GetCurrentProcess().getPointer();
                        // SE_KERNEL_OBJECT = 6, DACL_SECURITY_INFORMATION = 4
                        ok = Advapi.INSTANCE.SetSecurityInfo(self, 6, 4, null, null, dacl.getValue(), null) == 0;
                    }
                } finally { Kernel32.INSTANCE.LocalFree(descriptor.getValue()); }
            }
        } catch (RuntimeException | LinkageError unavailable) { ok = false; }
        if (last == null || last != ok) {
            LogUtils.getLogger().info("AcIvllas: process hardening {}", ok ? "applied" : "not applied");
            last = ok;
        }
        return ok;
    }
}
