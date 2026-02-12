package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;

import java.util.regex.Pattern;

/**
 * [工具类] Frida JS 片段版本兼容转换器。
 * <p>
 * <strong>使用边界：</strong>
 * 仅用于 ZAFrida 的“插入行为”（Snippet 插入、Template 勾选插入）前进行文本转换，
 * 不对用户手工编辑/粘贴的脚本做全局扫描替换。
 */
public final class FridaJsCompatibilityUtil {

    // 兼容转换思路贡献者：Log（社区贡献）

    /** Module.findExportByName(null, "symbol") */
    private static final Pattern FIND_EXPORT_WITH_NULL_MODULE = Pattern.compile(
            "Module\\s*\\.\\s*findExportByName\\s*\\(\\s*null\\s*,\\s*([\"'][^\"'\\r\\n]+[\"'])\\s*\\)"
    );

    /** Module.findExportByName("module", "symbol") */
    private static final Pattern FIND_EXPORT_WITH_MODULE_NAME = Pattern.compile(
            "Module\\s*\\.\\s*findExportByName\\s*\\(\\s*([\"'][^\"'\\r\\n]+[\"'])\\s*,\\s*([\"'][^\"'\\r\\n]+[\"'])\\s*\\)"
    );

    /**
     * 私有构造函数，禁止实例化。
     */
    private FridaJsCompatibilityUtil() {
    }

    /**
     * 按 Frida 主版本决定是否做 JS 兼容替换。
     * @param jsCode 原始 JS 文本
     * @param frida17OrLater 是否为 Frida17+
     * @return 兼容转换后的 JS 文本
     */
    public static @NotNull String adaptForFridaVersion(@NotNull String jsCode, boolean frida17OrLater) {
        if (!frida17OrLater) {
            return jsCode;
        }
        return adaptForFrida17(jsCode);
    }

    /**
     * 将 Frida16 风格的导出查找调用替换为 Frida17 风格。
     * @param jsCode 原始 JS 文本
     * @return 转换后的 JS 文本
     */
    public static @NotNull String adaptForFrida17(@NotNull String jsCode) {
        String adapted = FIND_EXPORT_WITH_NULL_MODULE
                .matcher(jsCode)
                .replaceAll("Module.getGlobalExportByName($1)");
        adapted = FIND_EXPORT_WITH_MODULE_NAME
                .matcher(adapted)
                .replaceAll("Process.getModuleByName($1).getExportByName($2)");
        return adapted;
    }
}
