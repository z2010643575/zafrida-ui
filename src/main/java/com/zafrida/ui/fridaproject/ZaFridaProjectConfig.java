package com.zafrida.ui.fridaproject;

import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaProcessScope;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaProjectConfig {
    public static final int VERSION = 1;

    public @NotNull String name = "";
    public @NotNull ZaFridaPlatform platform = ZaFridaPlatform.ANDROID;

    // 主脚本（相对项目文件夹）
    public @NotNull String mainScript = ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;

    // 上次调试目标（Android package / iOS bundle）
    public @Nullable String lastTarget = null;

    public @NotNull FridaConnectionMode connectionMode = FridaConnectionMode.USB;
    public @NotNull String remoteHost = "127.0.0.1";
    public int remotePort = 14725;

    public @Nullable String lastDeviceId = null;
    public @Nullable String lastDeviceHost = null;

    public boolean targetManual = true;

    public @NotNull FridaProcessScope processScope = FridaProcessScope.RUNNING_APPS;
}
