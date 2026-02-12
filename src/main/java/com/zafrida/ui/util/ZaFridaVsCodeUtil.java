package com.zafrida.ui.util;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.SystemInfo;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * [工具类] 用 VS Code 打开文件（自动探测可执行文件 + 支持用户在设置中指定路径）。
 * <p>
 * 说明：
 * - 这是 UI 层的轻量封装：负责组装命令并启动外部进程。
 * - 调用方应优先使用 {@link #openFileInVsCodeAsync(Project, String)}，避免阻塞 EDT。
 */
public final class ZaFridaVsCodeUtil {

    private ZaFridaVsCodeUtil() {
    }

    /**
     * 在后台线程中打开文件。
     */
    public static void openFileInVsCodeAsync(@NotNull Project project, @NotNull String filePath) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> openFileInVsCode(project, filePath));
    }

    /**
     * 打开文件（建议在后台线程调用）。
     */
    public static void openFileInVsCode(@NotNull Project project, @NotNull String filePath) {
        if (ZaStrUtil.isBlank(filePath)) {
            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", "No file path"));
            return;
        }

        File f = new File(filePath);
        if (!f.exists() || !f.isFile()) {
            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", String.format("File not found: %s", f.getAbsolutePath())));
            return;
        }

        VsCodeCommand cmd = resolveVsCodeCommand(f.getAbsolutePath());
        if (cmd == null) {
            ApplicationManager.getApplication().invokeLater(() -> ZaFridaNotifier.warn(
                    project,
                    "ZAFrida",
                    "VS Code not found. Please install it or set VS Code path in Settings | ZAFrida."
            ));
            return;
        }

        try {
            new ProcessBuilder(cmd.command).start();
        } catch (Throwable t) {
            String msg = t.getMessage();
            if (ZaStrUtil.isBlank(msg)) {
                msg = t.getClass().getName();
            }
            String finalMsg = msg;
            ApplicationManager.getApplication().invokeLater(() -> ZaFridaNotifier.warn(
                    project,
                    "ZAFrida",
                    String.format("Failed to open VS Code (%s): %s", cmd.debugName, finalMsg)
            ));
        }
    }

    private static final class VsCodeCommand {
        private final @NotNull String debugName;
        private final @NotNull List<String> command;

        private VsCodeCommand(@NotNull String debugName, @NotNull List<String> command) {
            this.debugName = debugName;
            this.command = command;
        }
    }

    private static @Nullable VsCodeCommand resolveVsCodeCommand(@NotNull String filePath) {
        ZaFridaSettingsState st = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
        String configured = st.vscodeExecutable;
        if (ZaStrUtil.isNotBlank(configured)) {
            String exec = resolveVsCodeExecutable(configured.trim());
            if (exec == null) {
                return null;
            }
            return buildVsCodeOpenCommand(exec, filePath, true);
        }

        String exec = autoDetectVsCodeExecutable();
        if (exec == null) {
            return null;
        }
        return buildVsCodeOpenCommand(exec, filePath, false);
    }

    private static @Nullable VsCodeCommand buildVsCodeOpenCommand(@NotNull String exec,
                                                                  @NotNull String filePath,
                                                                  boolean fromSettings) {
        String debugName = "VS Code (auto)";
        if (fromSettings) {
            debugName = "VS Code (settings)";
        }

        if (SystemInfo.isMac && exec.endsWith(".app")) {
            List<String> cmd = new ArrayList<>();
            cmd.add("open");
            cmd.add("-a");
            cmd.add(exec);
            cmd.add(filePath);
            return new VsCodeCommand(debugName, cmd);
        }

        if (SystemInfo.isWindows) {
            if (exec.toLowerCase().endsWith(".exe")) {
                List<String> cmd = new ArrayList<>();
                cmd.add(exec);
                cmd.add("-g");
                cmd.add(filePath);
                return new VsCodeCommand(debugName, cmd);
            }
            // code.cmd / code.bat / code (PATH) 需要走 cmd.exe
            List<String> cmd = new ArrayList<>();
            cmd.add("cmd.exe");
            cmd.add("/c");
            cmd.add(exec);
            cmd.add("-g");
            cmd.add(filePath);
            return new VsCodeCommand(debugName, cmd);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(exec);
        cmd.add("-g");
        cmd.add(filePath);
        return new VsCodeCommand(debugName, cmd);
    }

    private static @Nullable String resolveVsCodeExecutable(@NotNull String raw) {
        if (raw.isEmpty()) {
            return null;
        }

        // 允许用户配置 PATH 中的命令名（如 code / code.cmd）
        if (!hasPathSeparator(raw)) {
            File inPath = findInPathExecutable(raw);
            if (inPath != null) {
                return inPath.getAbsolutePath();
            }
            if (SystemInfo.isWindows) {
                String lower = raw.toLowerCase();
                if (!lower.endsWith(".cmd")) {
                    inPath = findInPathExecutable(raw + ".cmd");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
                if (!lower.endsWith(".exe")) {
                    inPath = findInPathExecutable(raw + ".exe");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
                if (!lower.endsWith(".bat")) {
                    inPath = findInPathExecutable(raw + ".bat");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
            }
            return null;
        }

        File f = new File(raw);
        if (f.exists()) {
            return f.getAbsolutePath();
        }
        return null;
    }

    private static @Nullable String autoDetectVsCodeExecutable() {
        // 1) PATH 优先
        File inPath = null;
        if (SystemInfo.isWindows) {
            inPath = findInPathExecutable("code.cmd");
            if (inPath == null) {
                inPath = findInPathExecutable("code");
            }
        } else {
            inPath = findInPathExecutable("code");
        }
        if (inPath != null) {
            return inPath.getAbsolutePath();
        }

        // 2) macOS: /Applications 下的 app（不依赖 PATH）
        if (SystemInfo.isMac) {
            File app = new File("/Applications/Visual Studio Code.app");
            if (app.exists() && app.isDirectory()) {
                return app.getAbsolutePath();
            }
            return null;
        }

        // 3) Windows: 常见安装目录
        if (SystemInfo.isWindows) {
            List<File> candidates = new ArrayList<>();
            String localAppData = System.getenv("LOCALAPPDATA");
            if (ZaStrUtil.isNotBlank(localAppData)) {
                candidates.add(new File(localAppData, "Programs\\Microsoft VS Code\\Code.exe"));
            }
            String programFiles = System.getenv("ProgramFiles");
            if (ZaStrUtil.isNotBlank(programFiles)) {
                candidates.add(new File(programFiles, "Microsoft VS Code\\Code.exe"));
            }
            String programFilesX86 = System.getenv("ProgramFiles(x86)");
            if (ZaStrUtil.isNotBlank(programFilesX86)) {
                candidates.add(new File(programFilesX86, "Microsoft VS Code\\Code.exe"));
            }

            for (File f : candidates) {
                if (f.exists() && f.isFile()) {
                    return f.getAbsolutePath();
                }
            }
        }

        return null;
    }

    private static boolean hasPathSeparator(@NotNull String s) {
        return s.indexOf('/') >= 0 || s.indexOf('\\') >= 0;
    }

    private static @Nullable File findInPathExecutable(@NotNull String name) {
        String pathEnv = System.getenv("PATH");
        if (ZaStrUtil.isBlank(pathEnv)) {
            return null;
        }
        String[] parts = pathEnv.split(Pattern.quote(File.pathSeparator));
        for (String dir : parts) {
            if (ZaStrUtil.isBlank(dir)) {
                continue;
            }
            File f = new File(dir.trim(), name);
            if (f.exists() && f.isFile()) {
                return f;
            }
        }
        return null;
    }
}

