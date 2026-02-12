package com.zafrida.ui.editor.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.util.FridaJsCompatibilityUtil;
import org.jetbrains.annotations.NotNull;

/**
 * [编辑器动作基类] Frida 代码片段插入的通用实现。
 * <p>
 * <strong>核心职责：</strong>
 * 1. 定义 IDE 编辑器右键菜单的 Action 行为。
 * 2. <strong>智能填充 (Smart Padding)：</strong> 自动检测光标前后的环境，在必要时自动补充换行符，防止插入的代码与现有代码粘连。
 * 3. <strong>事务管理：</strong> 封装 {@link WriteCommandAction}，确保文件修改操作符合 IntelliJ 线程规范。
 */
public abstract class InsertFridaSnippetAction extends AnAction {
    /** 插入的代码片段 */
    private final @NotNull String snippet;

    /**
     * 构造函数。
     * @param text 菜单显示文本
     * @param snippet 代码片段内容
     */
    protected InsertFridaSnippetAction(@NotNull String text, @NotNull String snippet) {
        super(text);
        this.snippet = snippet;
    }

    /**
     * 菜单执行逻辑。
     * @param e Action 事件
     */
    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        if (project == null || editor == null) {
            return;
        }

        Document document = editor.getDocument();
        if (!document.isWritable()) {
            return;
        }

        int offset = editor.getCaretModel().getOffset();
        String rawSnippet = getSnippet(e);
        String convertedSnippet = adaptSnippetForConfiguredFridaVersion(rawSnippet);
        String insertion = applyLinePadding(document, offset, convertedSnippet);
        WriteCommandAction.runWriteCommandAction(project, () -> document.insertString(offset, insertion));
        editor.getCaretModel().moveToOffset(offset + insertion.length());
    }

    /**
     * 获取当前插入的代码片段。
     * <p>
     * 默认返回构造函数传入的固定片段；子类可按上下文动态覆盖。
     *
     * @param e Action 事件
     * @return 片段内容
     */
    protected @NotNull String getSnippet(@NotNull AnActionEvent e) {
        return snippet;
    }

    /**
     * 按设置中的 Frida 版本对插入片段做兼容转换。
     * @param rawSnippet 原始片段（默认按 Frida16 编写）
     * @return 转换后的片段
     */
    private static @NotNull String adaptSnippetForConfiguredFridaVersion(@NotNull String rawSnippet) {
        ZaFridaSettingsService settingsService =
                ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        boolean frida17OrLater = settingsService != null && settingsService.isFrida17OrLater();
        return FridaJsCompatibilityUtil.adaptForFridaVersion(rawSnippet, frida17OrLater);
    }

    /**
     * 菜单可用性更新逻辑。
     * @param e Action 事件
     */
    @Override
    public void update(@NotNull AnActionEvent e) {
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        Project project = e.getProject();
        boolean enabled = editor != null && project != null && editor.getDocument().isWritable();
        e.getPresentation().setEnabledAndVisible(enabled);
    }

    /**
     * 根据光标位置为片段补齐换行。
     * @param document 编辑器文档
     * @param offset 插入位置
     * @param snippet 代码片段
     * @return 处理后的片段
     */
    private static @NotNull String applyLinePadding(@NotNull Document document, int offset, @NotNull String snippet) {
        CharSequence content = document.getCharsSequence();
        int lineNumber = document.getLineNumber(offset);
        int lineStart = document.getLineStartOffset(lineNumber);
        int lineEnd = document.getLineEndOffset(lineNumber);
        int firstNonWhitespace = findFirstNonWhitespace(content, lineStart, lineEnd);
        String lineIndent = content.subSequence(lineStart, firstNonWhitespace).toString();
        String adjustedSnippet = indentSnippet(snippet, lineIndent);
        StringBuilder builder = new StringBuilder();
        if (shouldAddLeadingNewline(content, offset, firstNonWhitespace)) {
            builder.append('\n');
            builder.append(lineIndent);
        }
        builder.append(adjustedSnippet);
        if (needsTrailingNewline(content, offset)) {
            builder.append('\n');
        }
        return builder.toString();
    }

    /**
     * 判断是否需要在前方补换行。
     * @param content 文档内容
     * @param offset 插入位置
     * @return true 表示需要
     */
    private static boolean shouldAddLeadingNewline(@NotNull CharSequence content, int offset, int firstNonWhitespace) {
        if (offset == 0) {
            return false;
        }
        if (content.charAt(offset - 1) == '\n') {
            return false;
        }
        if (offset <= firstNonWhitespace) {
            return false;
        }
        return true;
    }

    /**
     * 判断是否需要在后方补换行。
     * @param content 文档内容
     * @param offset 插入位置
     * @return true 表示需要
     */
    private static boolean needsTrailingNewline(@NotNull CharSequence content, int offset) {
        return offset < content.length() && content.charAt(offset) != '\n';
    }

    private static @NotNull String indentSnippet(@NotNull String snippet, @NotNull String lineIndent) {
        if (lineIndent.isEmpty()) {
            return snippet;
        }
        String[] lines = snippet.split("\n", -1);
        if (lines.length <= 1) {
            return snippet;
        }
        StringBuilder builder = new StringBuilder();
        builder.append(lines[0]);
        for (int index = 1; index < lines.length; index++) {
            builder.append('\n');
            if (!lines[index].isEmpty()) {
                builder.append(lineIndent);
            }
            builder.append(lines[index]);
        }
        return builder.toString();
    }

    private static int findFirstNonWhitespace(@NotNull CharSequence content, int lineStart, int lineEnd) {
        int index = lineStart;
        while (index < lineEnd) {
            char current = content.charAt(index);
            if (current != ' ' && current != '\t') {
                break;
            }
            index++;
        }
        return index;
    }
}
