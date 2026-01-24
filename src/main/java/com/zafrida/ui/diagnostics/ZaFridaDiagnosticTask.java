package com.zafrida.ui.diagnostics;

import org.jetbrains.annotations.NotNull;

/**
 * [接口] 诊断任务。
 */
public interface ZaFridaDiagnosticTask {

    /**
     * 执行检查。
     * @param context 诊断上下文
     * @return 诊断结果
     * @throws Exception 执行失败
     */
    @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) throws Exception;
}
