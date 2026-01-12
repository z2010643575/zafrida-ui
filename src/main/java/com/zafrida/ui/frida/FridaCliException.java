package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

public final class FridaCliException extends RuntimeException {

    private final @NotNull String commandLine;
    private final int exitCode;
    private final @NotNull String stdout;
    private final @NotNull String stderr;

    public FridaCliException(@NotNull String message,
                            @NotNull String commandLine,
                            int exitCode,
                            @NotNull String stdout,
                            @NotNull String stderr) {
        super(message);
        this.commandLine = commandLine;
        this.exitCode = exitCode;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public @NotNull String getCommandLine() {
        return commandLine;
    }

    public int getExitCode() {
        return exitCode;
    }

    public @NotNull String getStdout() {
        return stdout;
    }

    public @NotNull String getStderr() {
        return stderr;
    }
}
