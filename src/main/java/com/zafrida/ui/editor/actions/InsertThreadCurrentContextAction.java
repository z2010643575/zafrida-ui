package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

/**
 * [代码片段] 获取当前线程上下文（{@code Thread.currentContext()}）。
 * <p>
 * <strong>用途：</strong>
 * 在 Native Hook 或上下文缺失时手动获取当前线程上下文对象。
 */
public class InsertThreadCurrentContextAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = """
            Thread.currentContext();
            """;

    /**
     * 构造函数。
     */
    public InsertThreadCurrentContextAction() {
        super("Frida: Thread.currentContext", SNIPPET);
    }
}
