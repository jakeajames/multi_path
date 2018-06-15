# multi_path
multi_path with root, sandbox escape, codesign patch, bind shell, r/w for 11.0-11.2.6, nvram unlock (from Electra) and host_get_special_port 4 (from Electra), code injection (from Electra; injects the DummyPass tweak as a test; does not survive resprings; does not support tweaks depending on substrate). Call it a jailbreak if you want, or... a jelbrek

Credits to: Ian Beer for multi_path and mach_portal, Jonathan Levin for amfid patch, Jonathan Seals for find_kernel_base, Electra Team (especially stek29) and PsychoTea (@iBSparkes)

Includes a root shell. Connect with netcat. You can drop any binaries in the iosbinpack64 directory. All binaries must have at least these two entitlements:

    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>platform-application</key>
        <true/>
        <key>com.apple.private.security.container-required</key>
        <false/>
    </dict>
    </plist>

Note: Remounting on 11.3.x is not complete and doesn't work properly. If you want to test or mess with it you have to update offsets as stated in kern_utils.m.
