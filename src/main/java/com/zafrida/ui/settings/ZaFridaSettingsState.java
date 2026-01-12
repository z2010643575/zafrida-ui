package com.zafrida.ui.settings;

import java.util.ArrayList;
import java.util.List;

public final class ZaFridaSettingsState {

    public String fridaExecutable = "frida";
    public String fridaPsExecutable = "frida-ps";
    public String fridaLsDevicesExecutable = "frida-ls-devices";
    public String logsDirName = "zafrida-logs";
    public List<String> remoteHosts = new ArrayList<>();
}
