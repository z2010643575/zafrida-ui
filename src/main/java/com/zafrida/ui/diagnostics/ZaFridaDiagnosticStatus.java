package com.zafrida.ui.diagnostics;

/**
 * [枚举] 诊断项状态。
 */
public enum ZaFridaDiagnosticStatus {
    /** 等待执行 */
    PENDING,
    /** 执行中 */
    RUNNING,
    /** 成功 */
    SUCCESS,
    /** 失败 */
    FAILED,
    /** 已跳过 */
    SKIPPED
}
