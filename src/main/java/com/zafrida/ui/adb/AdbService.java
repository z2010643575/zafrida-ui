package com.zafrida.ui.adb;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.openapi.application.ApplicationManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * [Service] ADB 命令封装服务。
 * <p>
 * <strong>职责：</strong>
 * 1. 统一构建 adb 命令行（端口转发、强制停止、启动应用）。
 * 2. 在后台线程执行命令，并在 EDT 回调结果。
 * <p>
 * <strong>约束：</strong>
 * 仅负责命令与执行，不做 UI 交互；调用方负责提示与状态更新。
 */
public final class AdbService {

    private static final int DEFAULT_TIMEOUT_MS = 10_000;

    /**
     * 执行 adb forward 端口转发并回调结果。
     * @param port 端口号
     * @param info 信息日志
     * @param warn 警告日志
     * @param onDone 操作完成回调
     */
    public void forwardTcp(int port,
                           @NotNull Consumer<String> info,
                           @NotNull Consumer<String> warn,
                           @NotNull Runnable onDone) {
        GeneralCommandLine cmd = buildForwardCommand(port);
        info.accept("[ZAFrida] ADB forward: " + cmd.getCommandLineString());

        runAsync(cmd, result -> {
            if (result.exitCode != 0) {
                warn.accept("[ZAFrida] ADB forward failed (exitCode=" + result.exitCode + ")");
            } else {
                info.accept("[ZAFrida] ADB forward ready on port " + port);
            }
            if (!result.stdout.isBlank()) {
                info.accept("[ZAFrida] " + result.stdout);
            }
            if (!result.stderr.isBlank()) {
                warn.accept("[ZAFrida] " + result.stderr);
            }
            onDone.run();
        }, throwable -> {
            warn.accept("[ZAFrida] ADB forward failed: " + throwable.getMessage());
            onDone.run();
        });
    }

    /**
     * 通过 adb shell am force-stop 强制停止应用。
     * @param packageName 包名
     * @param deviceId 设备 ID（可为空）
     * @param info 信息日志
     * @param error 错误日志
     */
    public void forceStop(@NotNull String packageName,
                          @Nullable String deviceId,
                          @NotNull Consumer<String> info,
                          @NotNull Consumer<String> error) {
        GeneralCommandLine cmd = buildForceStopCommand(packageName, deviceId);
        info.accept("[ZAFrida] Force stop command: " + cmd.getCommandLineString());

        runAsync(cmd, result -> {
            if (result.exitCode == 0) {
                info.accept("[ZAFrida] Force stopped: " + packageName);
                if (!result.stdout.isBlank()) {
                    info.accept(result.stdout);
                }
            } else {
                String detail = !result.stderr.isBlank() ? result.stderr : result.stdout;
                if (detail.isBlank()) detail = "unknown error";
                error.accept("[ZAFrida] Force stop failed (exit=" + result.exitCode + "): " + detail);
            }
        }, throwable -> error.accept("[ZAFrida] Force stop failed: " + throwable.getMessage()));
    }

    /**
     * 通过 adb shell monkey 启动应用。
     * @param packageName 包名
     * @param deviceId 设备 ID（可为空）
     * @param info 信息日志
     * @param error 错误日志
     */
    public void openApp(@NotNull String packageName,
                        @Nullable String deviceId,
                        @NotNull Consumer<String> info,
                        @NotNull Consumer<String> error) {
        GeneralCommandLine cmd = buildOpenAppCommand(packageName, deviceId);
        info.accept("[ZAFrida] Open app command: " + cmd.getCommandLineString());

        runAsync(cmd, result -> {
            if (result.exitCode == 0) {
                info.accept("[ZAFrida] Opened app: " + packageName);
                if (!result.stdout.isBlank()) {
                    info.accept(result.stdout);
                }
            } else {
                String detail = !result.stderr.isBlank() ? result.stderr : result.stdout;
                if (detail.isBlank()) detail = "unknown error";
                error.accept("[ZAFrida] Open app failed (exit=" + result.exitCode + "): " + detail);
            }
        }, throwable -> error.accept("[ZAFrida] Open app failed: " + throwable.getMessage()));
    }

    private static @NotNull GeneralCommandLine buildForwardCommand(int port) {
        String tcp = "tcp:" + port;
        return new GeneralCommandLine("adb", "forward", tcp, tcp)
                .withCharset(StandardCharsets.UTF_8);
    }

    private static @NotNull GeneralCommandLine buildForceStopCommand(@NotNull String packageName,
                                                                     @Nullable String deviceId) {
        List<String> args = baseAdbArgs(deviceId);
        args.add("shell");
        args.add("am");
        args.add("force-stop");
        args.add(packageName);
        return new GeneralCommandLine(args)
                .withCharset(StandardCharsets.UTF_8);
    }

    private static @NotNull GeneralCommandLine buildOpenAppCommand(@NotNull String packageName,
                                                                   @Nullable String deviceId) {
        List<String> args = baseAdbArgs(deviceId);
        args.add("shell");
        args.add("monkey");
        args.add("-p");
        args.add(packageName);
        args.add("-c");
        args.add("android.intent.category.LAUNCHER");
        args.add("1");
        return new GeneralCommandLine(args)
                .withCharset(StandardCharsets.UTF_8);
    }

    private static @NotNull List<String> baseAdbArgs(@Nullable String deviceId) {
        List<String> args = new ArrayList<>();
        args.add("adb");
        if (deviceId != null && !deviceId.isBlank()) {
            args.add("-s");
            args.add(deviceId);
        }
        return args;
    }

    private void runAsync(@NotNull GeneralCommandLine cmd,
                          @NotNull Consumer<AdbResult> onDone,
                          @NotNull Consumer<Throwable> onError) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
                ProcessOutput out = handler.runProcess(DEFAULT_TIMEOUT_MS);
                AdbResult result = new AdbResult(out);
                ApplicationManager.getApplication().invokeLater(() -> onDone.accept(result));
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> onError.accept(t));
            }
        });
    }

    private static final class AdbResult {
        private final int exitCode;
        private final String stdout;
        private final String stderr;

        private AdbResult(@NotNull ProcessOutput out) {
            this.exitCode = out.getExitCode();
            this.stdout = trim(out.getStdout());
            this.stderr = trim(out.getStderr());
        }
    }

    private static @NotNull String trim(@Nullable String value) {
        return value == null ? "" : value.trim();
    }
}
