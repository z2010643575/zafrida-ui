package com.zafrida.ui.frida;

import com.intellij.execution.ExecutionException;
import com.intellij.execution.configurations.CommandLineTokenizer;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.OSProcessHandler;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class FridaCliService {

    private static final Logger LOG = Logger.getInstance(FridaCliService.class);

    private final ZaFridaSettingsService settings;

    public FridaCliService() {
        this.settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    public @NotNull List<FridaDevice> listDevices() {
        GeneralCommandLine cmd = buildLsDevicesCommandLine();
        CapturedOut out = runCapturing(cmd, 15_000);
        return FridaOutputParsers.parseDevices(out.stdout);
    }

    public @NotNull List<FridaProcess> listProcesses(@NotNull FridaDevice device, @NotNull FridaProcessScope scope) {
        GeneralCommandLine cmd = buildPsCommandLine(device, scope);
        CapturedOut out = runCapturing(cmd, 20_000);
        return FridaOutputParsers.parseProcesses(out.stdout);
    }

    public @NotNull GeneralCommandLine buildRunCommandLine(@NotNull FridaRunConfig config) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaExecutable)
                .withCharset(StandardCharsets.UTF_8);

        addDeviceArgs(cmd, config.getDevice());

        FridaRunMode mode = config.getMode();
        if (mode instanceof SpawnRunMode) {
            cmd.addParameters("-f", ((SpawnRunMode) mode).getIdentifier());
        } else if (mode instanceof AttachPidRunMode) {
            cmd.addParameters("-p", String.valueOf(((AttachPidRunMode) mode).getPid()));
        } else if (mode instanceof AttachNameRunMode) {
            cmd.addParameters("-n", ((AttachNameRunMode) mode).getName());
        } else {
            throw new IllegalArgumentException("Unknown run mode: " + mode);
        }

        cmd.addParameters("-l", config.getScriptPath());
        if (config.isNoPause()) {
            cmd.addParameter("--no-pause");
        }

        String extra = config.getExtraArgs();
        if (extra != null && !extra.trim().isEmpty()) {
            CommandLineTokenizer tok = new CommandLineTokenizer(extra);
            while (tok.hasMoreTokens()) {
                cmd.addParameter(tok.nextToken());
            }
        }

        return cmd;
    }

    public @NotNull OSProcessHandler createRunProcessHandler(@NotNull FridaRunConfig config) {
        try {
            return new OSProcessHandler(buildRunCommandLine(config));
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    private @NotNull GeneralCommandLine buildLsDevicesCommandLine() {
        ZaFridaSettingsState s = settings.getState();
        return new GeneralCommandLine(s.fridaLsDevicesExecutable)
                .withCharset(StandardCharsets.UTF_8);
    }

    private @NotNull GeneralCommandLine buildPsCommandLine(@NotNull FridaDevice device, @NotNull FridaProcessScope scope) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaPsExecutable)
                .withCharset(StandardCharsets.UTF_8);

        addDeviceArgs(cmd, device);

        switch (scope) {
            case RUNNING_PROCESSES -> {
                // default
            }
            case RUNNING_APPS -> cmd.addParameter("-a");
            case INSTALLED_APPS -> cmd.addParameters("-a", "-i");
        }

        return cmd;
    }

    private void addDeviceArgs(@NotNull GeneralCommandLine cmd, @NotNull FridaDevice device) {
        if (device.getMode() == FridaDeviceMode.HOST) {
            String host = device.getHost();
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Device host is null/blank");
            }
            cmd.addParameters("-H", host);
            return;
        }
        cmd.addParameters("-D", device.getId());
    }

    private CapturedOut runCapturing(@NotNull GeneralCommandLine cmd, int timeoutMs) {
        CapturingProcessHandler handler = null;
        try {
            handler = new CapturingProcessHandler(cmd);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
        var out = handler.runProcess(timeoutMs);

        String stdout = out.getStdout() != null ? out.getStdout() : "";
        String stderr = out.getStderr() != null ? out.getStderr() : "";
        int exitCode = out.getExitCode();

        if (exitCode != 0) {
            String cmdLine = cmd.getCommandLineString();
            LOG.warn("Frida tool failed: exit=" + exitCode + " cmd=" + cmdLine + " stderr=" + stderr + " stdout=" + stdout);
            throw new FridaCliException(
                    "Command failed (exit=" + exitCode + "): " + cmdLine + "\n" + stderr,
                    cmdLine,
                    exitCode,
                    stdout,
                    stderr
            );
        }

        return new CapturedOut(stdout, stderr, exitCode);
    }

    private static final class CapturedOut {
        final String stdout;
        final String stderr;
        final int exitCode;

        CapturedOut(String stdout, String stderr, int exitCode) {
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitCode = exitCode;
        }
    }
}
