package com.zafrida.ui.diagnostics;

import org.jetbrains.annotations.NotNull;

import java.util.List;

/**
 * [回调] 诊断执行状态监听。
 */
public interface ZaFridaDiagnosticsListener {

    /**
     * 单项状态变化回调。
     * @param item 诊断项
     */
    void onItemUpdated(@NotNull ZaFridaDiagnosticItem item);

    /**
     * 全部完成回调。
     * @param items 诊断项列表
     */
    void onAllCompleted(@NotNull List<ZaFridaDiagnosticItem> items);
}
