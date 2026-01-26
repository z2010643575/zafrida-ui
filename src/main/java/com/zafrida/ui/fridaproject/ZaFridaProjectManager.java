package com.zafrida.ui.fridaproject;

import com.intellij.openapi.components.Service;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.util.ZaStrUtil;
import com.intellij.util.messages.Topic;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * [项目核心] ZAFrida 自研项目系统管理器。
 * <p>
 * <strong>架构说明：</strong>
 * ZAFrida 引入了轻量级 "子项目" 概念，独立于 IDE 的 Project 结构。
 * <ul>
 * <li><strong>Workspace:</strong> 存储在 {@code zafrida-workspace.xml}，记录项目列表。</li>
 * <li><strong>Project:</strong> 存储在具体目录的 {@code zafrida-project.xml}，记录 App 特有的 Hook 配置。</li>
 * </ul>
 * <p>
 * <strong>职责：</strong> 负责项目的创建、加载、切换激活状态以及配置文件的读写原子性操作。
 */
@Service(Service.Level.PROJECT)
public final class ZaFridaProjectManager {

    /** 项目切换事件主题 */
    public static final Topic<ZaFridaProjectListener> TOPIC =
            Topic.create("ZAFrida.ProjectSelection", ZaFridaProjectListener.class);

    /** 当前 IntelliJ/PyCharm 项目实例 */
    private final Project project;
    /** 项目存储辅助类(@link ZaFridaProjectStorage) */
    private final ZaFridaProjectStorage storage = new ZaFridaProjectStorage();
    /** 配置读写串行队列（原子锁保证顺序） */
    private final ConfigTaskQueue configTaskQueue;

    /** 当前工作区配置 */
    private ZaFridaWorkspaceConfig workspace;
    /** 按名称索引的项目映射 */
    private final Map<String, ZaFridaFridaProject> byName = new LinkedHashMap<>();
    /** 当前激活的项目 */
    private @Nullable ZaFridaFridaProject active;

    /**
     * 构造函数，初始化项目管理器并加载工作区配置。
     * @param project
     */
    public ZaFridaProjectManager(@NotNull Project project) {
        this.project = project;
        this.configTaskQueue = new ConfigTaskQueue(project);
        this.workspace = new ZaFridaWorkspaceConfig();
        reloadAsync(null);
    }

    /**
     * 重新加载工作区配置及项目列表（后台线程）。
     * <p>
     * 读取完成后会在 UI 线程触发一次项目切换事件，便于刷新界面。
     */
    public void reloadAsync(@Nullable Runnable uiAfter) {
        AtomicReference<ZaFridaFridaProject> activeRef = new AtomicReference<>();
        runConfigTask(() -> {
            ZaFridaWorkspaceConfig loaded = storage.loadWorkspace(project);
            Map<String, ZaFridaFridaProject> loadedByName = new LinkedHashMap<>();
            for (ZaFridaFridaProject p : loaded.projects) {
                loadedByName.put(p.getName(), p);
            }
            ZaFridaFridaProject loadedActive = null;
            if (loaded.lastSelected != null) {
                loadedActive = loadedByName.get(loaded.lastSelected);
            }
            synchronized (this) {
                workspace = loaded;
                byName.clear();
                byName.putAll(loadedByName);
                active = loadedActive;
            }
            activeRef.set(loadedActive);
        }, () -> {
            project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(activeRef.get());
            if (uiAfter != null) {
                uiAfter.run();
            }
        }, null);
    }

    /**
     * 列出当前工作区中的所有项目。
     * synchronized 确保线程安全。
     * @return 项目列表
     */
    public synchronized @NotNull List<ZaFridaFridaProject> listProjects() {
        return new ArrayList<>(byName.values());
    }

    /**
     * 获取当前激活的项目。
     * synchronized 确保线程安全。
     * @return 当前激活的项目，若无则返回 null
     */
    public synchronized @Nullable ZaFridaFridaProject getActiveProject() {
        return active;
    }

    /**
     * 根据目录查找对应的项目。
     * @param dir 目标目录
     * @return 对应的项目，若不存在则返回 null
     */
    public void findProjectByDirAsync(@NotNull VirtualFile dir, @NotNull Consumer<ZaFridaFridaProject> uiConsumer) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(findProjectByDirInternal(dir)), () -> uiConsumer.accept(ref.get()), null);
    }

    private @Nullable ZaFridaFridaProject findProjectByDirInternal(@NotNull VirtualFile dir) {
        String rel = toRelativeDirInternal(dir);
        if (rel == null) {
            return null;
        }
        synchronized (this) {
            for (ZaFridaFridaProject p : workspace.projects) {
                if (rel.equals(p.getRelativeDir())) {
                    return p;
                }
            }
        }
        return null;
    }

    /**
     * 注册一个已存在的项目目录。
     * @param dir 目标目录
     * @param activate 是否激活该项目
     * @return 注册的项目实例，若目录无效则返回 null
     */
    public void registerExistingProjectAsync(@NotNull VirtualFile dir,
                                             boolean activate,
                                             @NotNull Consumer<ZaFridaFridaProject> uiConsumer) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(registerExistingProjectInternal(dir, activate)), () -> {
            ZaFridaFridaProject result = ref.get();
            if (activate && result != null) {
                project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(result);
            }
            uiConsumer.accept(result);
        }, null);
    }

    private @Nullable ZaFridaFridaProject registerExistingProjectInternal(@NotNull VirtualFile dir, boolean activate) {
        // 计算相对路径
        String rel = toRelativeDirInternal(dir);
        if (rel == null) {
            return null;
        }

        // 读取项目配置
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        String name;
        if (ZaStrUtil.isBlank(cfg.name)) {
            name = dir.getName();
        } else {
            name = cfg.name;
        }
        ZaFridaPlatform platform = inferPlatform(rel, cfg.platform);

        ZaFridaFridaProject target = null;
        boolean added = false;
        synchronized (this) {
            for (ZaFridaFridaProject p : workspace.projects) {
                if (rel.equals(p.getRelativeDir())) {
                    target = p;
                    break;
                }
            }
            if (target == null) {
                target = new ZaFridaFridaProject(name, platform, rel);
                byName.put(target.getName(), target);
                ZaFridaFridaProject finalTarget = target;
                workspace.projects.removeIf(x -> x.getName().equals(finalTarget.getName()));
                workspace.projects.add(target);
                added = true;
            }
        }

        // 保存 workspace（若新增且不激活）
        if (added && !activate) {
            storage.saveWorkspace(project, workspace);
        }
        // 激活项目（若需要）
        if (activate && target != null) {
            setActiveProjectInternal(target);
        }
        return target;
    }

    /**
     * 设置当前激活的项目。
     * synchronized 确保线程安全。
     * @param p 要激活的项目，若为 null 则表示无激活项目
     */
    public void setActiveProjectAsync(@Nullable ZaFridaFridaProject p) {
        setActiveProjectAsync(p, null);
    }

    public void setActiveProjectAsync(@Nullable ZaFridaFridaProject p, @Nullable Runnable uiAfter) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>(p);
        runConfigTask(() -> setActiveProjectInternal(ref.get()), () -> {
            project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(ref.get());
            if (uiAfter != null) {
                uiAfter.run();
            }
        }, null);
    }

    private void setActiveProjectInternal(@Nullable ZaFridaFridaProject p) {
        synchronized (this) {
            active = p;
            if (p == null) {
                workspace.lastSelected = null;
            } else {
                workspace.lastSelected = p.getName();
            }
        }
        storage.saveWorkspace(project, workspace);
    }

    /**
     * 创建并激活一个新项目。
     * @param name 项目名称
     * @param platform 目标平台
     * @return 创建并激活的项目实例
     */
    public void createAndActivateAsync(@NotNull String name,
                                       @NotNull ZaFridaPlatform platform,
                                       @NotNull Consumer<ZaFridaFridaProject> uiConsumer,
                                       @NotNull Consumer<Throwable> errorConsumer) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>();
        runConfigTask(() -> {
            try {
                ref.set(createAndActivateInternal(name, platform));
            } catch (Throwable t) {
                throw t;
            }
        }, () -> {
            ZaFridaFridaProject created = ref.get();
            if (created == null) {
                errorConsumer.accept(new IllegalStateException("Create project failed"));
                return;
            }
            project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(created);
            uiConsumer.accept(created);
        }, null, errorConsumer);
    }

    private @NotNull ZaFridaFridaProject createAndActivateInternal(@NotNull String name, @NotNull ZaFridaPlatform platform) {
        // 处理掉名称中的非法字符
        String safeName = sanitizeName(name);
        // 获取IntelliJ/PyCharm IDE使用该插件的项目目录
        VirtualFile base = project.getBaseDir();
        // 确保项目目录存在(这个几乎不可能为空)
        if (base == null) {
            throw new IllegalStateException("No project base dir");
        }

        // 构造相对目录路径
        String rootFolder = platform.rootFolderName();
        String relDir = String.format("%s/%s", rootFolder, safeName);

        // 先构造对象（不触发写）
        ZaFridaFridaProject fp = new ZaFridaFridaProject(safeName, platform, relDir);

        // 写操作：创建目录、写 project config、写默认脚本、写 workspace 文件
        com.intellij.openapi.command.WriteCommandAction.runWriteCommandAction(project, () -> {
            VirtualFile projectDir = null;
            try {
                projectDir = VfsUtil.createDirectoryIfMissing(base, relDir);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            // 1) project config(项目的一些默认配置)
            ZaFridaProjectConfig cfg = new ZaFridaProjectConfig();
            cfg.name = safeName;
            cfg.platform = platform;
            cfg.mainScript = ZaFridaProjectFiles.defaultMainScriptName(safeName);
            cfg.processScope = FridaProcessScope.RUNNING_APPS;
            cfg.connectionMode = FridaConnectionMode.USB;
            cfg.remoteHost = "127.0.0.1";
            cfg.remotePort = 14725;
            cfg.targetManual = true;
            cfg.spawnMode = true;
            cfg.extraArgs = "";

            // 这里不要再内部再套 WriteCommandAction（避免嵌套）
            storage.saveProjectConfigNoWriteAction(projectDir, cfg);

            // 2) default script
            ensureFileNoWriteAction(projectDir, cfg.mainScript, defaultAgentSkeleton());

            // 3) 更新 workspace in-memory + 写 workspace 文件
            synchronized (this) {
                byName.put(fp.getName(), fp);
                workspace.projects.removeIf(x -> x.getName().equals(fp.getName()));
                workspace.projects.add(fp);
                workspace.lastSelected = fp.getName();
                active = fp;
            }
            storage.saveWorkspaceNoWriteAction(base, workspace);

            // refresh vfs
            // 刷新虚拟文件系统
            projectDir.refresh(false, true);
            base.refresh(false, true);
        });

        return fp;
    }


    /**
     * 加载指定项目的配置。
     * @param p 目标项目
     * @param uiConsumer UI 线程回调
     */
    public void loadProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                       @NotNull Consumer<ZaFridaProjectConfig> uiConsumer) {
        loadProjectConfigAsync(p, uiConsumer, null);
    }

    public void loadProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                       @NotNull Consumer<ZaFridaProjectConfig> uiConsumer,
                                       @Nullable ModalityState modality) {
        AtomicReference<ZaFridaProjectConfig> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(loadProjectConfigInternal(p)), () -> uiConsumer.accept(ref.get()), modality);
    }

    /**
     * 加载 UI 侧需要的项目快照（配置 + 目录 + 脚本文件）。
     * @param p 目标项目
     * @param uiConsumer UI 线程回调
     */
    public void loadProjectUiStateAsync(@NotNull ZaFridaFridaProject p,
                                        @NotNull Consumer<ProjectUiState> uiConsumer) {
        loadProjectUiStateAsync(p, uiConsumer, null);
    }

    public void loadProjectUiStateAsync(@NotNull ZaFridaFridaProject p,
                                        @NotNull Consumer<ProjectUiState> uiConsumer,
                                        @Nullable ModalityState modality) {
        AtomicReference<ProjectUiState> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(loadProjectUiStateInternal(p)), () -> uiConsumer.accept(ref.get()), modality);
    }

    /**
     * 更新指定项目的配置（后台线程）。
     * @param p 目标项目
     * @param mutator 用于修改配置的函数
     */
    public void updateProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                         @NotNull Consumer<ZaFridaProjectConfig> mutator) {
        updateProjectConfigAsync(p, mutator, null);
    }

    public void updateProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                         @NotNull Consumer<ZaFridaProjectConfig> mutator,
                                         @Nullable Runnable uiAfter) {
        runConfigTask(() -> updateProjectConfigInternal(p, mutator), uiAfter, null);
    }

    /**
     * 更新主脚本路径（后台线程，内部转换为相对路径）。
     * @param p 目标项目
     * @param file 脚本文件
     */
    public void updateMainScriptPathAsync(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        updateProjectConfigAsync(p, cfg -> {
            String rel = toProjectRelativePathInternal(p, file);
            if (ZaStrUtil.isNotBlank(rel)) {
                cfg.mainScript = rel;
            }
        });
    }

    /**
     * 更新附加脚本路径（后台线程，内部转换为相对路径）。
     * @param p 目标项目
     * @param file 脚本文件
     */
    public void updateAttachScriptPathAsync(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        updateProjectConfigAsync(p, cfg -> {
            String rel = toProjectRelativePathInternal(p, file);
            if (ZaStrUtil.isNotBlank(rel)) {
                cfg.attachScript = rel;
            }
        });
    }

    /**
     * 解析 Run 脚本（后台线程）。
     * @param p 目标项目
     * @param targetId 目标标识
     * @param gadgetMode 是否为 Gadget 模式
     * @param uiConsumer UI 线程回调
     */
    public void resolveRunScriptFileAsync(@NotNull ZaFridaFridaProject p,
                                          @NotNull String targetId,
                                          boolean gadgetMode,
                                          @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(resolveRunScriptFileInternal(p, targetId, gadgetMode)),
                () -> uiConsumer.accept(ref.get()),
                null);
    }

    /**
     * 解析 Attach 脚本（后台线程）。
     * @param p 目标项目
     * @param uiConsumer UI 线程回调
     */
    public void resolveAttachScriptFileAsync(@NotNull ZaFridaFridaProject p,
                                             @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(resolveAttachScriptFileInternal(p)), () -> uiConsumer.accept(ref.get()), null);
    }

    /**
     * 确保 Run 主脚本存在并可用（后台线程）。
     * @param p 目标项目
     * @param targetId 目标标识
     * @param uiConsumer UI 线程回调
     */
    public void ensureMainScriptForTargetAsync(@NotNull ZaFridaFridaProject p,
                                               @NotNull String targetId,
                                               @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(ensureMainScriptForTargetInternal(p, targetId)),
                () -> uiConsumer.accept(ref.get()),
                null);
    }

    /**
     * 自动补全默认主脚本（后台线程）。
     * @param p 目标项目
     * @param uiAfter UI 线程回调
     */
    public void ensureDefaultMainScriptAsync(@NotNull ZaFridaFridaProject p, @Nullable Runnable uiAfter) {
        runConfigTask(() -> ensureDefaultMainScriptInternal(p), uiAfter, null);
    }

    /**
     * 解析项目的实际目录（后台线程）。
     * @param p 目标项目
     * @param uiConsumer UI 线程回调
     */
    public void resolveProjectDirAsync(@NotNull ZaFridaFridaProject p, @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(resolveProjectDirInternal(p)), () -> uiConsumer.accept(ref.get()), null);
    }

    /** UI 侧需要的项目快照。 */
    public static final class ProjectUiState {
        private final @NotNull ZaFridaProjectConfig config;
        private final @Nullable VirtualFile projectDir;
        private final @Nullable VirtualFile mainScriptFile;
        private final @Nullable VirtualFile attachScriptFile;

        private ProjectUiState(@NotNull ZaFridaProjectConfig config,
                               @Nullable VirtualFile projectDir,
                               @Nullable VirtualFile mainScriptFile,
                               @Nullable VirtualFile attachScriptFile) {
            this.config = config;
            this.projectDir = projectDir;
            this.mainScriptFile = mainScriptFile;
            this.attachScriptFile = attachScriptFile;
        }

        public @NotNull ZaFridaProjectConfig getConfig() {
            return config;
        }

        public @Nullable VirtualFile getProjectDir() {
            return projectDir;
        }

        public @Nullable VirtualFile getMainScriptFile() {
            return mainScriptFile;
        }

        public @Nullable VirtualFile getAttachScriptFile() {
            return attachScriptFile;
        }
    }

    private @NotNull ZaFridaProjectConfig loadProjectConfigInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = p.getName();
            c.platform = p.getPlatform();
            return c;
        }
        ZaFridaProjectConfig c = storage.loadProjectConfig(project, dir);
        c.name = p.getName();
        c.platform = p.getPlatform();
        return c;
    }

    private ProjectUiState loadProjectUiStateInternal(@NotNull ZaFridaFridaProject p) {
        ZaFridaProjectConfig cfg = loadProjectConfigInternal(p);
        VirtualFile dir = resolveProjectDirInternal(p);
        VirtualFile mainScript = null;
        VirtualFile attachScript = null;
        if (dir != null) {
            if (ZaStrUtil.isNotBlank(cfg.mainScript)) {
                VirtualFile cand = dir.findFileByRelativePath(cfg.mainScript);
                if (cand != null && !cand.isDirectory()) {
                    mainScript = cand;
                }
            }
            if (ZaStrUtil.isNotBlank(cfg.attachScript)) {
                VirtualFile cand = dir.findFileByRelativePath(cfg.attachScript);
                if (cand != null && !cand.isDirectory()) {
                    attachScript = cand;
                }
            }
        }
        return new ProjectUiState(cfg, dir, mainScript, attachScript);
    }

    private void updateProjectConfigInternal(@NotNull ZaFridaFridaProject p,
                                             @NotNull Consumer<ZaFridaProjectConfig> mutator) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return;
        }
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        mutator.accept(cfg);
        cfg.name = p.getName();
        cfg.platform = p.getPlatform();
        storage.saveProjectConfig(project, dir, cfg);
    }

    private @Nullable VirtualFile resolveProjectDirInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile base = project.getBaseDir();
        if (base == null) {
            return null;
        }
        return base.findFileByRelativePath(p.getRelativeDir());
    }

    private @Nullable String toProjectRelativePathInternal(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return null;
        }
        return storage.relativize(dir, file);
    }

    private @Nullable VirtualFile resolveRunScriptFileInternal(@NotNull ZaFridaFridaProject p,
                                                               @NotNull String targetId,
                                                               boolean gadgetMode) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return null;
        }
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        if (ZaStrUtil.isNotBlank(cfg.mainScript)) {
            VirtualFile cand = dir.findFileByRelativePath(cfg.mainScript);
            if (cand != null && !cand.isDirectory()) {
                return cand;
            }
        }
        if (gadgetMode) {
            return null;
        }
        return ensureMainScriptForTargetInternal(p, targetId);
    }

    private @Nullable VirtualFile resolveAttachScriptFileInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return null;
        }
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        if (ZaStrUtil.isBlank(cfg.attachScript)) {
            return null;
        }
        VirtualFile cand = dir.findFileByRelativePath(cfg.attachScript);
        if (cand != null && !cand.isDirectory()) {
            return cand;
        }
        return null;
    }

    private void ensureDefaultMainScriptInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return;
        }
        ZaFridaProjectConfig cfg = loadProjectConfigInternal(p);
        if (hasValidMainScriptInternal(dir, cfg)) {
            return;
        }
        String picked = pickDefaultMainScriptInternal(dir);
        String updated;
        if (picked == null) {
            updated = "";
        } else {
            updated = picked;
        }
        if (!updated.equals(cfg.mainScript)) {
            cfg.mainScript = updated;
            storage.saveProjectConfig(project, dir, cfg);
        }
    }

    private boolean hasValidMainScriptInternal(@NotNull VirtualFile dir, @NotNull ZaFridaProjectConfig cfg) {
        if (ZaStrUtil.isBlank(cfg.mainScript)) {
            return false;
        }
        VirtualFile cand = dir.findFileByRelativePath(cfg.mainScript);
        return cand != null && !cand.isDirectory();
    }

    private @Nullable String pickDefaultMainScriptInternal(@NotNull VirtualFile dir) {
        String sameName = ZaFridaProjectFiles.defaultMainScriptName(dir.getName());
        VirtualFile match = dir.findChild(sameName);
        if (match != null && !match.isDirectory()) {
            return sameName;
        }

        VirtualFile agent = dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT);
        if (agent != null && !agent.isDirectory()) {
            return ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;
        }

        VirtualFile[] children = dir.getChildren();
        if (children == null || children.length == 0) {
            return null;
        }

        Arrays.sort(children, Comparator.comparing(VirtualFile::getName, String.CASE_INSENSITIVE_ORDER));
        for (VirtualFile child : children) {
            if (!child.isDirectory() && "js".equalsIgnoreCase(child.getExtension())) {
                return child.getName();
            }
        }
        return null;
    }

    private void runConfigTask(@NotNull Runnable ioTask,
                               @Nullable Runnable uiTask,
                               @Nullable ModalityState modality) {
        runConfigTask(ioTask, uiTask, modality, null);
    }

    private void runConfigTask(@NotNull Runnable ioTask,
                               @Nullable Runnable uiTask,
                               @Nullable ModalityState modality,
                               @Nullable Consumer<Throwable> errorConsumer) {
        configTaskQueue.submit(() -> {
            try {
                ioTask.run();
            } catch (Throwable t) {
                if (errorConsumer != null) {
                    ApplicationManager.getApplication().invokeLater(() -> {
                        if (!project.isDisposed()) {
                            errorConsumer.accept(t);
                        }
                    }, ModalityState.NON_MODAL);
                }
                return;
            }
            if (uiTask == null) {
                return;
            }
            ModalityState state;
            if (modality != null) {
                state = modality;
            } else {
                state = ModalityState.NON_MODAL;
            }
            ApplicationManager.getApplication().invokeLater(() -> {
                if (!project.isDisposed()) {
                    uiTask.run();
                }
            }, state);
        });
    }

    /**
     * 配置读写的串行队列，使用原子状态保证顺序与互斥。
     */
    private static final class ConfigTaskQueue {
        private final Project project;
        private final AtomicBoolean running = new AtomicBoolean(false);
        private final ConcurrentLinkedQueue<Runnable> queue = new ConcurrentLinkedQueue<>();

        private ConfigTaskQueue(@NotNull Project project) {
            this.project = project;
        }

        private void submit(@NotNull Runnable task) {
            queue.add(task);
            trySchedule();
        }

        private void trySchedule() {
            if (!running.compareAndSet(false, true)) {
                return;
            }
            scheduleNext();
        }

        private void scheduleNext() {
            Runnable next = queue.poll();
            if (next == null) {
                running.set(false);
                if (!queue.isEmpty()) {
                    trySchedule();
                }
                return;
            }
            ApplicationManager.getApplication().executeOnPooledThread(() -> {
                try {
                    if (!project.isDisposed()) {
                        next.run();
                    }
                } finally {
                    scheduleNext();
                }
            });
        }
    }

    /** 创建文件（无写操作版本）。
     * 这个版本用于在已有写操作的上下文中调用，避免嵌套写操作。
     * @param dir 目标目录
     * @param name 文件名
     * @param content 文件内容
     */
    private static void ensureFileNoWriteAction(@NotNull VirtualFile dir, @NotNull String name, @NotNull String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (Throwable ignore) {}
    }


    /**
     * 包名末段生成默认主脚本：com.su.fridatest -> fridatest.js
     * 若当前 mainScript 还是默认 agent.js，则升级为该名称（不覆盖用户自定义主脚本）
     */
    private @NotNull VirtualFile ensureMainScriptForTargetInternal(@NotNull ZaFridaFridaProject p,
                                                                   @NotNull String targetId) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            throw new IllegalStateException("Project dir not found");
        }

        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        String defaultMain = ZaFridaProjectFiles.defaultMainScriptName(p.getName());
        String oldMain;
        if (ZaStrUtil.isBlank(cfg.mainScript)) {
            oldMain = defaultMain;
        } else {
            oldMain = cfg.mainScript;
        }

        String leaf = targetLeaf(targetId);
        String autoName = String.format("%s.js", leaf);

        // 仅在仍是默认 agent.js 时自动切换
        if (ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT.equals(oldMain) && !autoName.equals(oldMain)) {
            cfg.mainScript = autoName;
            storage.saveProjectConfig(project, dir, cfg);
            ensureFile(dir, autoName, defaultAgentSkeleton());
            VirtualFile created = dir.findChild(autoName);
            if (created != null) {
                return created;
            }
        }

        if (ZaStrUtil.isBlank(cfg.mainScript)) {
            cfg.mainScript = defaultMain;
            storage.saveProjectConfig(project, dir, cfg);
        }
        ensureFile(dir, cfg.mainScript, defaultAgentSkeleton());
        VirtualFile vf = dir.findChild(cfg.mainScript);
        if (vf != null) {
            return vf;
        }

        // fallback
        // 回退处理
        ensureFile(dir, defaultMain, defaultAgentSkeleton());
        VirtualFile fallback = dir.findChild(defaultMain);
        if (fallback != null) {
            return fallback;
        }
        ensureFile(dir, ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT, defaultAgentSkeleton());
        return Objects.requireNonNull(dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT));
    }

    // ---------------- utils ----------------

    /**
     * 清理项目名称，移除非法文件名字符。
     * @param name
     * @return String
     */
    private static String sanitizeName(String name) {
        String s = name.trim();
        s = s.replaceAll("[\\\\/:*?\"<>|]", "_");
        if (s.isEmpty()) s = "ZAFridaProject";
        return s;
    }

    /**
     * 提取目标标识的末段作为脚本命名参考。
     * 例如：com.example.app -> app
     * @param target 目标标识
     * @return 末段字符串
     */
    private static String targetLeaf(String target) {
        String t = target.trim();
        int idx = t.lastIndexOf('.');
        if (idx >= 0 && idx + 1 < t.length()) return t.substring(idx + 1);
        return t;
    }

    /** 创建文件（有写操作版本）。
     * 这个版本会在内部执行写操作。
     * @param dir 目标目录
     * @param name 文件名
     * @param content 文件内容
     */
    private static void ensureFile(VirtualFile dir, String name, String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (Throwable ignore) {}
    }

    /** 将目录转换为相对于项目根目录的路径。
     * @param dir 目标目录
     * @return 相对路径字符串，若无法解析则返回 null
     */
    private @Nullable String toRelativeDirInternal(@NotNull VirtualFile dir) {
        VirtualFile base = project.getBaseDir();
        if (base == null) {
            return null;
        }
        String rel = VfsUtilCore.getRelativePath(dir, base, '/');
        if (ZaStrUtil.isBlank(rel)) {
            return null;
        }
        return rel;
    }

    /** 根据相对目录推断平台类型。
     * @param relativeDir 相对目录
     * @param fallback 回退平台
     * @return 推断的平台类型
     */
    private static @NotNull ZaFridaPlatform inferPlatform(@NotNull String relativeDir, @NotNull ZaFridaPlatform fallback) {
        String rel = relativeDir.replace('\\', '/');
        if (rel.equals("ios") || rel.startsWith("ios/")) return ZaFridaPlatform.IOS;
        if (rel.equals("android") || rel.startsWith("android/")) return ZaFridaPlatform.ANDROID;
        return fallback;
    }

    /** 默认 Agent 脚本骨架。 */
    private static String defaultAgentSkeleton() {
        return """
                // ZAFrida default agent
                'use strict';
                console.log('[ZAFrida] agent loaded');
                """;
    }
}
