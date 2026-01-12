package com.zafrida.ui.logging;

import com.intellij.openapi.application.ApplicationManager;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class ZaFridaLogPaths {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private ZaFridaLogPaths() {
    }

    public static @Nullable Path ensureLogsDir(@NotNull String projectBasePath) {
        ZaFridaSettingsService settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        String dirName = settings.getState().logsDirName;
        if (dirName == null || dirName.isBlank()) dirName = "zafrida-logs";
        try {
            Path dir = Paths.get(projectBasePath, dirName);
            Files.createDirectories(dir);
            return dir;
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static @Nullable Path newSessionLogFile(@NotNull String projectBasePath) {
        Path dir = ensureLogsDir(projectBasePath);
        if (dir == null) return null;
        String name = "zafrida_" + LocalDateTime.now().format(FMT) + ".log";
        Path file = dir.resolve(name);
        try {
            if (!Files.exists(file)) {
                Files.createFile(file);
            }
        } catch (Throwable ignored) {
            // ignore
        }
        return file;
    }
}
