package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

/**
 * [代码片段] 打印 Native Backtrace（ACCURATE 模式）。
 * <p>
 * <strong>用途：</strong>
 * 在 {@code Interceptor.attach} 的 {@code onEnter/onLeave} 中输出调用栈，定位 Native 调用来源。
 */
public class InsertBacktraceAccurateAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = """
            console.log('backtrace called from:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            """;

    /**
     * 构造函数。
     */
    public InsertBacktraceAccurateAction() {
        super("Frida: backtrace (ACCURATE)", SNIPPET);
    }
}
