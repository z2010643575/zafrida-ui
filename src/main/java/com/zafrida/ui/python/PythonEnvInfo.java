package com.zafrida.ui.python;

import org.jetbrains.annotations.NotNull;

import java.util.Collections;
import java.util.List;

/**
 * Resolved information about the project's selected Python interpreter environment.
 *
 * <p>This is used to run frida-tools (frida / frida-ps / frida-ls-devices) from the
 * same virtualenv/conda environment that PyCharm uses for the current project.</p>
 */
public final class PythonEnvInfo {

    private final @NotNull String pythonHome;
    private final @NotNull String envRoot;
    private final @NotNull List<String> toolDirs;
    private final @NotNull List<String> pathEntries;

    public PythonEnvInfo(@NotNull String pythonHome,
                         @NotNull String envRoot,
                         @NotNull List<String> toolDirs,
                         @NotNull List<String> pathEntries) {
        this.pythonHome = pythonHome;
        this.envRoot = envRoot;
        this.toolDirs = Collections.unmodifiableList(toolDirs);
        this.pathEntries = Collections.unmodifiableList(pathEntries);
    }

    public @NotNull String getPythonHome() {
        return pythonHome;
    }

    public @NotNull String getEnvRoot() {
        return envRoot;
    }

    /**
     * Directories where console scripts are expected (bin / Scripts).
     */
    public @NotNull List<String> getToolDirs() {
        return toolDirs;
    }

    /**
     * Directories to prepend into PATH when spawning processes.
     */
    public @NotNull List<String> getPathEntries() {
        return pathEntries;
    }
}
