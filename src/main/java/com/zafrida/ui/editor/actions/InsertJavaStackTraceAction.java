package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

/**
 * [代码片段] 打印当前 Java 调用栈（{@code Log.getStackTraceString + Throwable}）。
 * <p>
 * <strong>用途：</strong>
 * 在 Java Hook 场景中快速输出当前调用路径，辅助定位调用链。
 */
public class InsertJavaStackTraceAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = """
            console.log(Java.use('android.util.Log')
                    .getStackTraceString(Java.use('java.lang.Throwable')
                            .$new()));
            """;

    /**
     * 构造函数。
     */
    public InsertJavaStackTraceAction() {
        super("Frida: print Java stack trace", SNIPPET);
    }
}
