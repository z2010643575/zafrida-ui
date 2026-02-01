package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

/**
 * [代码片段] 打印 Native Backtrace（FUZZY 模式）。
 * <p>
 * <strong>用途：</strong>
 * 当 ACCURATE 性能开销较大或不可用时，使用 FUZZY 模式快速定位调用路径。
 */
public class InsertBacktraceFuzzyAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = """
            console.log('backtrace called from:\\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            """;

    /**
     * 构造函数。
     */
    public InsertBacktraceFuzzyAction() {
        super("Frida: backtrace (FUZZY)", SNIPPET);
    }
}
