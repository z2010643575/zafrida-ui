package com.zafrida.ui.settings;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.options.SearchableConfigurable;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JComponent;

public final class ZaFridaSettingsConfigurable implements SearchableConfigurable {

    private final ZaFridaSettingsService settingsService;
    private @Nullable ZaFridaSettingsComponent component;

    public ZaFridaSettingsConfigurable() {
        this.settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    @Override
    public @NotNull String getId() {
        return "com.zafrida.ui.settings";
    }

    @Override
    public String getDisplayName() {
        return "ZAFrida";
    }

    @Override
    public @Nullable JComponent createComponent() {
        ZaFridaSettingsComponent c = new ZaFridaSettingsComponent();
        c.reset(settingsService.getState());
        this.component = c;
        return c.getPanel();
    }

    @Override
    public boolean isModified() {
        if (component == null) return false;

        ZaFridaSettingsState copy = new ZaFridaSettingsState();
        // start from current state
        copy.fridaExecutable = settingsService.getState().fridaExecutable;
        copy.fridaPsExecutable = settingsService.getState().fridaPsExecutable;
        copy.fridaLsDevicesExecutable = settingsService.getState().fridaLsDevicesExecutable;
        copy.logsDirName = settingsService.getState().logsDirName;
        copy.remoteHosts = settingsService.getRemoteHosts();

        component.applyTo(copy);

        // compare
        ZaFridaSettingsState current = settingsService.getState();
        if (!safeEq(copy.fridaExecutable, current.fridaExecutable)) return true;
        if (!safeEq(copy.fridaPsExecutable, current.fridaPsExecutable)) return true;
        if (!safeEq(copy.fridaLsDevicesExecutable, current.fridaLsDevicesExecutable)) return true;
        if (!safeEq(copy.logsDirName, current.logsDirName)) return true;

        if (copy.remoteHosts == null && current.remoteHosts != null && !current.remoteHosts.isEmpty()) return true;
        if (copy.remoteHosts != null && current.remoteHosts == null && !copy.remoteHosts.isEmpty()) return true;
        if (copy.remoteHosts != null && current.remoteHosts != null && !copy.remoteHosts.equals(current.remoteHosts)) return true;

        return false;
    }

    @Override
    public void apply() {
        if (component == null) return;
        ZaFridaSettingsState newState = new ZaFridaSettingsState();
        newState.fridaExecutable = settingsService.getState().fridaExecutable;
        newState.fridaPsExecutable = settingsService.getState().fridaPsExecutable;
        newState.fridaLsDevicesExecutable = settingsService.getState().fridaLsDevicesExecutable;
        newState.logsDirName = settingsService.getState().logsDirName;
        newState.remoteHosts = settingsService.getRemoteHosts();

        component.applyTo(newState);
        settingsService.loadState(newState);
    }

    @Override
    public void reset() {
        if (component != null) {
            component.reset(settingsService.getState());
        }
    }

    @Override
    public void disposeUIResources() {
        component = null;
    }

    private static boolean safeEq(String a, String b) {
        if (a == null) return b == null;
        return a.equals(b);
    }
}
