package com.zafrida.ui.session;

import com.intellij.execution.process.ProcessHandler;
import org.jetbrains.annotations.NotNull;

public final class RunningSession {

    private final @NotNull ProcessHandler processHandler;
    private final @NotNull String logFilePath;

    public RunningSession(@NotNull ProcessHandler processHandler, @NotNull String logFilePath) {
        this.processHandler = processHandler;
        this.logFilePath = logFilePath;
    }

    public @NotNull ProcessHandler getProcessHandler() {
        return processHandler;
    }

    public @NotNull String getLogFilePath() {
        return logFilePath;
    }
}
