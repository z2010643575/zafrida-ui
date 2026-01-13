package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.util.IconLoader;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.zafrida.ui.frida.*;
import com.zafrida.ui.fridaproject.*;
import com.zafrida.ui.fridaproject.ui.CreateZaFridaProjectDialog;
import com.zafrida.ui.fridaproject.ui.ZaFridaProjectSettingsDialog;
import com.zafrida.ui.session.RunningSession;
import com.zafrida.ui.session.ZaFridaSessionService;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.ui.components.SearchableComboBoxPanel;
import com.zafrida.ui.ui.render.DeviceCellRenderer;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import com.intellij.openapi.util.text.StringUtil;

public final class ZaFridaRunPanel extends JPanel implements Disposable {

    private static final int MIN_WIDTH = 200;
    private static final int PREFERRED_WIDTH = 280;

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsolePanel consolePanel;
    private final @NotNull ZaFridaTemplatePanel templatePanel;

    private final @NotNull FridaCliService fridaCli;
    private final @NotNull ZaFridaSessionService sessionService;

    private final ComboBox<FridaDevice> deviceCombo = new ComboBox<>();
    private final JButton refreshDevicesBtn = createSmallButton(AllIcons.Actions.Refresh, "Refresh devices");
    private final JButton addRemoteBtn = createSmallButton(AllIcons.General.Add, "Add remote host");

    private final JBTextField scriptField = new JBTextField();
    private final JButton chooseScriptBtn = createSmallButton(AllIcons.Actions.MenuOpen, "Choose script");

    private final JRadioButton spawnRadio = new JRadioButton("Spawn", true);
    private final JRadioButton attachRadio = new JRadioButton("Attach");
    private final JBTextField targetField = new JBTextField();

    private final JCheckBox noPauseCheck = new JCheckBox("--no-pause", true);
    private final JBTextField extraArgsField = new JBTextField();

    private final JButton runBtn = new JButton("Run");
    private final JButton stopBtn = new JButton("Stop");
    private final JButton clearConsoleBtn = createSmallButton(AllIcons.Actions.GC, "Clear console");

    private final JBLabel logFileLabel = new JBLabel("Log: (not started)");

    private @Nullable VirtualFile scriptFile;

    private boolean printedToolchainInfo = false;

    private final ZaFridaProjectManager fridaProjectManager;
    private final SearchableComboBoxPanel<ZaFridaFridaProject> fridaProjectSelector =
            new SearchableComboBoxPanel<>(p -> p == null ? "" : p.getName());
    private final JButton newFridaProjectBtn = createSmallButton(AllIcons.Actions.NewFolder, "New project");
    private final JButton projectSettingsBtn = createSmallButton(AllIcons.General.Settings, "Project settings");
    private final JButton languageToggleBtn = createSmallButton(
            IconLoader.getIcon("/META-INF/icons/lang-toggle.svg", ZaFridaRunPanel.class),
            "中文 / English"
    );
    private boolean updatingFridaProjectSelector = false;

    private static JButton createSmallButton(Icon icon, String tooltip) {
        JButton btn = new JButton(icon);
        btn.setToolTipText(tooltip);
        btn.setMargin(JBUI.emptyInsets());
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        Dimension size = new Dimension(JBUI.scale(24), JBUI.scale(24));
        btn.setPreferredSize(size);
        btn.setMinimumSize(size);
        btn.setMaximumSize(size);
        return btn;
    }

    public ZaFridaRunPanel(@NotNull Project project,
                           @NotNull ZaFridaConsolePanel consolePanel,
                           @NotNull ZaFridaTemplatePanel templatePanel) {
        super(new BorderLayout());
        this.project = project;
        this.consolePanel = consolePanel;
        this.templatePanel = templatePanel;

        this.fridaCli = ApplicationManager.getApplication().getService(FridaCliService.class);
        this.sessionService = project.getService(ZaFridaSessionService.class);
        this.fridaProjectManager = project.getService(ZaFridaProjectManager.class);

        setMinimumSize(new Dimension(JBUI.scale(MIN_WIDTH), 0));
        setPreferredSize(new Dimension(JBUI.scale(PREFERRED_WIDTH), Integer.MAX_VALUE));

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(JBUI.Borders.empty(4));

        // Toolbar
        mainPanel.add(buildToolbar());
        mainPanel.add(Box.createVerticalStrut(JBUI.scale(8)));

        // Form sections
        mainPanel.add(buildSection("Project", buildProjectContent()));
        mainPanel.add(buildSection("Device", buildDeviceContent()));
        mainPanel.add(buildSection("Script", buildScriptContent()));
        mainPanel.add(buildSection("Mode", buildModeContent()));
        mainPanel.add(buildSection("Extra", buildExtraContent()));
        mainPanel.add(Box.createVerticalStrut(JBUI.scale(8)));
        mainPanel.add(buildActionButtons());

        // Glue to push everything to top
        mainPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(JBUI.Borders.empty());
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(JBUI.scale(16));

        add(scrollPane, BorderLayout.CENTER);

        logFileLabel.setBorder(JBUI.Borders.empty(4));
        logFileLabel.setForeground(UIUtil.getContextHelpForeground());
        add(logFileLabel, BorderLayout.SOUTH);

        initUiState();
        bindActions();
        subscribeToFridaProjectChanges();
        reloadFridaProjectsIntoUi();
        applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        reloadDevicesAsync();
    }

    private JPanel buildToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(2), 0));
        toolbar.setAlignmentX(Component.LEFT_ALIGNMENT);
        toolbar.setMaximumSize(new Dimension(Integer.MAX_VALUE, JBUI.scale(28)));
        toolbar.add(newFridaProjectBtn);
        toolbar.add(projectSettingsBtn);
        toolbar.add(Box.createHorizontalStrut(JBUI.scale(8)));
        toolbar.add(languageToggleBtn);
        return toolbar;
    }

    private JPanel buildSection(String title, JComponent content) {
        JPanel section = new JPanel(new BorderLayout());
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.setBorder(JBUI.Borders.empty(2, 0));

        JBLabel label = new JBLabel(title);
        label.setForeground(UIUtil.getContextHelpForeground());
        label.setBorder(JBUI.Borders.empty(0, 0, 2, 0));

        section.add(label, BorderLayout.NORTH);
        section.add(content, BorderLayout.CENTER);
        section.setMaximumSize(new Dimension(Integer.MAX_VALUE, section.getPreferredSize().height));

        return section;
    }

    private JPanel buildProjectContent() {
        JPanel panel = new JPanel(new BorderLayout(JBUI.scale(4), 0));
        fridaProjectSelector.setMaximumSize(new Dimension(Integer.MAX_VALUE, JBUI.scale(28)));
        panel.add(fridaProjectSelector, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildDeviceContent() {
        JPanel panel = new JPanel(new BorderLayout(JBUI.scale(4), 0));

        deviceCombo.setRenderer(new DeviceCellRenderer());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, JBUI.scale(2), 0));
        buttons.add(refreshDevicesBtn);
        buttons.add(addRemoteBtn);

        panel.add(deviceCombo, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildScriptContent() {
        JPanel panel = new JPanel(new BorderLayout(JBUI.scale(4), 0));

        scriptField.setEditable(false);

        panel.add(scriptField, BorderLayout.CENTER);
        panel.add(chooseScriptBtn, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildModeContent() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        JPanel radioPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(8), 0));
        radioPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        ButtonGroup group = new ButtonGroup();
        group.add(spawnRadio);
        group.add(attachRadio);

        spawnRadio.setToolTipText("Spawn process (-f)");
        attachRadio.setToolTipText("Attach to PID (-p)");

        radioPanel.add(spawnRadio);
        radioPanel.add(attachRadio);

        JPanel targetPanel = new JPanel(new BorderLayout());
        targetPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        targetPanel.setBorder(JBUI.Borders.emptyTop(4));

        JBLabel targetLabel = new JBLabel("Target:");
        targetLabel.setBorder(JBUI.Borders.emptyRight(4));

        targetField.setToolTipText("Package name (spawn) or PID (attach)");

        targetPanel.add(targetLabel, BorderLayout.WEST);
        targetPanel.add(targetField, BorderLayout.CENTER);

        panel.add(radioPanel);
        panel.add(targetPanel);
        return panel;
    }

    private JPanel buildExtraContent() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        noPauseCheck.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(noPauseCheck);

        JPanel argsPanel = new JPanel(new BorderLayout());
        argsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        argsPanel.setBorder(JBUI.Borders.emptyTop(4));

        JBLabel argsLabel = new JBLabel("Args:");
        argsLabel.setBorder(JBUI.Borders.emptyRight(4));

        extraArgsField.setToolTipText("Extra args, e.g. --realm=emulated");

        argsPanel.add(argsLabel, BorderLayout.WEST);
        argsPanel.add(extraArgsField, BorderLayout.CENTER);

        panel.add(argsPanel);
        return panel;
    }

    private JPanel buildActionButtons() {
        JPanel panel = new JPanel(new GridLayout(1, 3, JBUI.scale(4), 0));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, JBUI.scale(32)));

        runBtn.setIcon(AllIcons.Actions.Execute);
        stopBtn.setIcon(AllIcons.Actions.Suspend);
        stopBtn.setEnabled(false);

        panel.add(runBtn);
        panel.add(stopBtn);
        panel.add(clearConsoleBtn);

        return panel;
    }

    private void initUiState() {
        // Already configured in build methods
    }

    private void bindActions() {
        refreshDevicesBtn.addActionListener(e -> reloadDevicesAsync());

        addRemoteBtn.addActionListener(e -> {
            String host = Messages.showInputDialog(this, "host:port", "Add Frida Remote Host", null);
            if (host == null) return;
            String h = host.trim();
            if (h.isEmpty()) return;
            ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).addRemoteHost(h);
            reloadDevicesAsync();
        });

        clearConsoleBtn.addActionListener(e -> consolePanel.clear());

        runBtn.addActionListener(e -> runFrida());
        stopBtn.addActionListener(e -> stopFrida());

        fridaProjectSelector.addActionListener(e -> {
            if (updatingFridaProjectSelector) return;
            fridaProjectManager.setActiveProject(fridaProjectSelector.getSelectedItem());
        });
        newFridaProjectBtn.addActionListener(e -> createNewFridaProject());
        projectSettingsBtn.addActionListener(e -> openProjectSettings());
        languageToggleBtn.addActionListener(e -> Messages.showInfoMessage(
                project,
                "Switch UI language (中文/English) is coming soon.",
                "ZAFrida"
        ));
        chooseScriptBtn.addActionListener(e -> {
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            VirtualFile initial = active != null ? fridaProjectManager.resolveProjectDir(active) : null;

            VirtualFile file = null;
            if (initial != null) {
                FileChooserDescriptor d = new FileChooserDescriptor(true, false, false, false, false, false);
                d.withFileFilter(vf -> "js".equalsIgnoreCase(vf.getExtension()));
                file = FileChooser.chooseFile(d, project, initial);
            }
            if (file == null) file = ProjectFileUtil.chooseJavaScriptFile(project);
            if (file == null) return;

            setScriptFile(file);

            if (active != null) {
                String rel = fridaProjectManager.toProjectRelativePath(active, file);
                if (rel != null) fridaProjectManager.updateProjectConfig(active, c -> c.mainScript = rel);
            }
        });
    }

    private void subscribeToFridaProjectChanges() {
        project.getMessageBus().connect(this).subscribe(ZaFridaProjectManager.TOPIC, new ZaFridaProjectListener() {
            @Override
            public void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    reloadFridaProjectsIntoUi();
                    applyActiveFridaProjectToUi(newProject);
                });
            }
        });
    }

    private void reloadFridaProjectsIntoUi() {
        updatingFridaProjectSelector = true;
        try {
            List<ZaFridaFridaProject> list = fridaProjectManager.listProjects();
            fridaProjectSelector.setItems(list);
            fridaProjectSelector.setSelectedItem(fridaProjectManager.getActiveProject());

            fridaProjectSelector.setEnabled(true);
            newFridaProjectBtn.setEnabled(true);
        } finally {
            updatingFridaProjectSelector = false;
        }
    }

    private void applyActiveFridaProjectToUi(@Nullable ZaFridaFridaProject active) {
        updatingFridaProjectSelector = true;
        try {
            fridaProjectSelector.setSelectedItem(active);
        } finally {
            updatingFridaProjectSelector = false;
        }

        templatePanel.setCurrentPlatform(active == null ? null : active.getPlatform());

        if (active == null) {
            return;
        }

        ZaFridaProjectConfig cfg = fridaProjectManager.loadProjectConfig(active);

        if (!StringUtil.isEmptyOrSpaces(cfg.lastTarget)) {
            targetField.setText(cfg.lastTarget);
        }

        VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
        if (dir != null) {
            String rel = cfg.mainScript;
            if (!StringUtil.isEmptyOrSpaces(rel)) {
                VirtualFile f = dir.findFileByRelativePath(rel);
                if (f != null && !f.isDirectory()) {
                    setScriptFile(f);
                } else {
                    consolePanel.warn("[ZAFrida] Main script not found in project: " + rel);
                }
            }
        }
    }

    private void createNewFridaProject() {
        CreateZaFridaProjectDialog dialog = new CreateZaFridaProjectDialog(project);
        if (!dialog.showAndGet()) return;

        String name = dialog.getProjectName();
        if (name.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Project name is empty");
            return;
        }

        ZaFridaPlatform platform = dialog.getPlatform();

        try {
            ZaFridaFridaProject created = fridaProjectManager.createAndActivate(name, platform);

            reloadFridaProjectsIntoUi();
            applyActiveFridaProjectToUi(created);

            consolePanel.info("[ZAFrida] Created project: " + created.getName() + " (" + created.getRelativeDir() + ")");
        } catch (Throwable t) {
            consolePanel.error("[ZAFrida] Create project failed: " + t.getMessage());
            ZaFridaNotifier.error(project, "ZAFrida", "Create project failed: " + t.getMessage());
        }
    }

    private void openProjectSettings() {
        ZaFridaProjectSettingsDialog dialog = new ZaFridaProjectSettingsDialog(
                project,
                fridaProjectManager,
                fridaCli,
                () -> (FridaDevice) deviceCombo.getSelectedItem()
        );
        if (dialog.showAndGet()) {
            applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        }
    }

    private void setScriptFile(@NotNull VirtualFile file) {
        this.scriptFile = file;
        this.scriptField.setText(file.getName());
        this.scriptField.setToolTipText(file.getPath());
        this.templatePanel.setCurrentScriptFile(file);
    }

    private void printToolchainInfoOnce() {
        if (printedToolchainInfo) return;
        printedToolchainInfo = true;

        PythonEnvInfo env = ProjectPythonEnvResolver.resolve(project);
        if (env == null) {
            consolePanel.warn("[ZAFrida] Project Python interpreter env not detected. Using IDE/system PATH for frida-tools.");
            return;
        }

        consolePanel.info("[ZAFrida] Project Python: " + env.getPythonHome());
        if (!env.getPathEntries().isEmpty()) {
            consolePanel.info("[ZAFrida] Project PATH prepend: " + String.join(File.pathSeparator, env.getPathEntries()));
        }

        ZaFridaSettingsState st = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
        String ls = ProjectPythonEnvResolver.findTool(env, st.fridaLsDevicesExecutable);
        String ps = ProjectPythonEnvResolver.findTool(env, st.fridaPsExecutable);
        String frida = ProjectPythonEnvResolver.findTool(env, st.fridaExecutable);

        if (ls != null) {
            consolePanel.info("[ZAFrida] Resolved frida-ls-devices: " + ls);
        } else {
            consolePanel.warn("[ZAFrida] frida-ls-devices not found in project interpreter; will fallback to system PATH if available.");
        }
        if (ps != null) {
            consolePanel.info("[ZAFrida] Resolved frida-ps: " + ps);
        }
        if (frida != null) {
            consolePanel.info("[ZAFrida] Resolved frida: " + frida);
        }
    }

    private void reloadDevicesAsync() {
        disableControls(true);
        printToolchainInfoOnce();
        consolePanel.info("[ZAFrida] Loading devices...");

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                List<FridaDevice> devices = new ArrayList<>(fridaCli.listDevices(project));
                var remotes = ApplicationManager.getApplication()
                        .getService(ZaFridaSettingsService.class)
                        .getRemoteHosts();
                for (String host : remotes) {
                    devices.add(new FridaDevice("remote:" + host, "remote", "Remote", FridaDeviceMode.HOST, host));
                }

                ApplicationManager.getApplication().invokeLater(() -> {
                    deviceCombo.removeAllItems();
                    for (FridaDevice d : devices) deviceCombo.addItem(d);
                    if (!devices.isEmpty()) deviceCombo.setSelectedIndex(0);
                    consolePanel.info("[ZAFrida] Devices loaded: " + devices.size());
                    disableControls(false);
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    consolePanel.error("[ZAFrida] Load devices failed: " + t.getMessage());
                    disableControls(false);
                });
            }
        });
    }

    private void runFrida() {
        FridaDevice dev = (FridaDevice) deviceCombo.getSelectedItem();
        if (dev == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No device selected");
            return;
        }

        String target = targetField.getText() != null ? targetField.getText().trim() : "";
        if (target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();

        VirtualFile script = scriptFile != null ? scriptFile : templatePanel.getCurrentScriptFile();

        if (script == null && active != null) {
            ZaFridaProjectConfig pc = fridaProjectManager.loadProjectConfig(active);
            VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
            if (dir != null && pc != null && !StringUtil.isEmptyOrSpaces(pc.mainScript)) {
                VirtualFile cand = dir.findFileByRelativePath(pc.mainScript);
                if (cand != null && !cand.isDirectory()) {
                    setScriptFile(cand);
                    script = cand;
                }
            }
        }

        if (script == null && active != null && spawnRadio.isSelected()) {
            VirtualFile auto = fridaProjectManager.ensureMainScriptForTarget(active, target);
            setScriptFile(auto);
            script = auto;
        }

        if (script == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Choose a script file first");
            return;
        }

        if (active != null && spawnRadio.isSelected()) {
            fridaProjectManager.updateProjectConfig(active, c -> c.lastTarget = target);
        }
        if (active != null) {
            String rel = fridaProjectManager.toProjectRelativePath(active, script);
            if (rel != null) {
                fridaProjectManager.updateProjectConfig(active, c -> c.mainScript = rel);
            }
        }

        FridaRunMode mode;
        if (spawnRadio.isSelected()) {
            mode = new SpawnRunMode(target);
        } else {
            try {
                mode = new AttachPidRunMode(Integer.parseInt(target));
            } catch (NumberFormatException e) {
                ZaFridaNotifier.warn(project, "ZAFrida", "Attach mode requires PID integer");
                return;
            }
        }

        FridaRunConfig cfg = new FridaRunConfig(
                dev,
                mode,
                script.getPath(),
                noPauseCheck.isSelected(),
                extraArgsField.getText() != null ? extraArgsField.getText() : ""
        );

        try {
            RunningSession session = sessionService.start(
                    cfg,
                    consolePanel.getConsoleView(),
                    consolePanel::info,
                    consolePanel::error
            );

            session.getProcessHandler().addProcessListener(sessionService.createUiStateListener(() -> {
                runBtn.setEnabled(true);
                stopBtn.setEnabled(false);
            }));

            runBtn.setEnabled(false);
            stopBtn.setEnabled(true);
            logFileLabel.setText("Log: " + session.getLogFilePath());
            consolePanel.info("[ZAFrida] Log file: " + session.getLogFilePath());
        } catch (Throwable t) {
            consolePanel.error("[ZAFrida] Start failed: " + t.getMessage());
            ZaFridaNotifier.error(project, "ZAFrida", "Start failed: " + t.getMessage());
        }
    }

    private void stopFrida() {
        sessionService.stop();
        runBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        consolePanel.info("[ZAFrida] Stopped");
    }

    private void disableControls(boolean disabled) {
        deviceCombo.setEnabled(!disabled);
        refreshDevicesBtn.setEnabled(!disabled);
        addRemoteBtn.setEnabled(!disabled);
    }

    @Override
    public void dispose() {
        // project service handles stop
    }
}