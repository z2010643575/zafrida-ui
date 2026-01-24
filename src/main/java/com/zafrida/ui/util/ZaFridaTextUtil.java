package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;

/**
 * [工具类] 文本校验工具。
 * <p>
 * <strong>范围：</strong>
 * 仅提供轻量、无状态的字符串校验。
 */
public final class ZaFridaTextUtil {

    private ZaFridaTextUtil() {
    }

    /**
     * 判断字符串是否为纯数字且非空。
     * @param value 待校验文本
     * @return 是否为纯数字
     */
    public static boolean isNumeric(@NotNull String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) return false;
        }
        return !value.isEmpty();
    }
}
