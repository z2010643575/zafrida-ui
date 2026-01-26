package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * [工具类] 常用字符串处理（参考 Hutool StrUtil 常用能力）。
 * <p>
 * <strong>范围：</strong>
 * 提供轻量、无状态的字符串处理方法。
 */
public final class ZaStrUtil {

    public static final int INDEX_NOT_FOUND = -1;
    public static final String NULL = "null";
    public static final String EMPTY = "";
    public static final String SPACE = " ";

    private ZaStrUtil() {
    }

    private static boolean isBlankChar(char c) {
        return Character.isWhitespace(c) || Character.isSpaceChar(c) || c == '\uFEFF';
    }

    private static boolean isArrayEmpty(@Nullable Object[] array) {
        return array == null || array.length == 0;
    }

    private static boolean isCharArrayEmpty(@Nullable char[] array) {
        return array == null || array.length == 0;
    }

    private static boolean containsChar(@NotNull char[] array, char target) {
        for (char c : array) {
            if (c == target) return true;
        }
        return false;
    }

    private static boolean isSeparator(char c, char symbol) {
        return c == symbol || c == '_' || c == '-' || c == ' ';
    }

    /**
     * 判断字符串是否为空白（null/空/仅空白字符）。
     * @param str 待校验文本
     * @return 是否为空白
     */
    public static boolean isBlank(@Nullable CharSequence str) {
        if (str == null) return true;
        int length = str.length();
        if (length == 0) return true;
        for (int i = 0; i < length; i++) {
            if (!isBlankChar(str.charAt(i))) return false;
        }
        return true;
    }

    /**
     * 判断字符串是否非空白。
     * @param str 待校验文本
     * @return 是否非空白
     */
    public static boolean isNotBlank(@Nullable CharSequence str) {
        return !isBlank(str);
    }

    /**
     * 是否存在空白字符串。
     * @param strs 文本列表
     * @return 是否存在空白
     */
    public static boolean hasBlank(@Nullable CharSequence... strs) {
        if (isArrayEmpty(strs)) return true;
        for (CharSequence str : strs) {
            if (isBlank(str)) return true;
        }
        return false;
    }

    /**
     * 是否全部为空白。
     * @param strs 文本列表
     * @return 是否全部为空白
     */
    public static boolean isAllBlank(@Nullable CharSequence... strs) {
        if (isArrayEmpty(strs)) return true;
        for (CharSequence str : strs) {
            if (isNotBlank(str)) return false;
        }
        return true;
    }

    /**
     * 判断字符串是否为空（null/长度为 0）。
     * @param str 待校验文本
     * @return 是否为空
     */
    public static boolean isEmpty(@Nullable CharSequence str) {
        return str == null || str.length() == 0;
    }

    /**
     * 判断字符串是否非空。
     * @param str 待校验文本
     * @return 是否非空
     */
    public static boolean isNotEmpty(@Nullable CharSequence str) {
        return !isEmpty(str);
    }

    /**
     * null 转空字符串。
     * @param str 文本
     * @return 非 null 文本
     */
    public static @NotNull String emptyIfNull(@Nullable CharSequence str) {
        return nullToEmpty(str);
    }

    /**
     * null 转空字符串。
     * @param str 文本
     * @return 非 null 文本
     */
    public static @NotNull String nullToEmpty(@Nullable CharSequence str) {
        return nullToDefault(str, EMPTY);
    }

    /**
     * null 转指定默认值。
     * @param str 文本
     * @param defaultStr 默认值
     * @return 转换结果
     */
    public static @Nullable String nullToDefault(@Nullable CharSequence str, @Nullable String defaultStr) {
        return str == null ? defaultStr : str.toString();
    }

    /**
     * 空字符串转默认值。
     * @param str 文本
     * @param defaultStr 默认值
     * @return 转换结果
     */
    public static @Nullable String emptyToDefault(@Nullable CharSequence str, @Nullable String defaultStr) {
        return isEmpty(str) ? defaultStr : str.toString();
    }

    /**
     * 空白字符串转默认值。
     * @param str 文本
     * @param defaultStr 默认值
     * @return 转换结果
     */
    public static @Nullable String blankToDefault(@Nullable CharSequence str, @Nullable String defaultStr) {
        return isBlank(str) ? defaultStr : str.toString();
    }

    /**
     * 空字符串转 null。
     * @param str 文本
     * @return 转换结果
     */
    public static @Nullable String emptyToNull(@Nullable CharSequence str) {
        return isEmpty(str) ? null : str.toString();
    }

    /**
     * 是否存在空字符串。
     * @param strs 文本列表
     * @return 是否存在空
     */
    public static boolean hasEmpty(@Nullable CharSequence... strs) {
        if (isArrayEmpty(strs)) return true;
        for (CharSequence str : strs) {
            if (isEmpty(str)) return true;
        }
        return false;
    }

    /**
     * 是否全部为空字符串。
     * @param strs 文本列表
     * @return 是否全部为空
     */
    public static boolean isAllEmpty(@Nullable CharSequence... strs) {
        if (isArrayEmpty(strs)) return true;
        for (CharSequence str : strs) {
            if (isNotEmpty(str)) return false;
        }
        return true;
    }

    /**
     * 是否全部为非空字符串。
     * @param args 文本列表
     * @return 是否全部非空
     */
    public static boolean isAllNotEmpty(@Nullable CharSequence... args) {
        return !hasEmpty(args);
    }

    /**
     * 是否全部为非空白字符串。
     * @param args 文本列表
     * @return 是否全部非空白
     */
    public static boolean isAllNotBlank(@Nullable CharSequence... args) {
        return !hasBlank(args);
    }

    /**
     * 是否为 null 或 undefined（字符串）。
     * @param str 文本
     * @return 是否为 null/undefined
     */
    public static boolean isNullOrUndefined(@Nullable CharSequence str) {
        return str == null || isNullOrUndefinedStr(str);
    }

    /**
     * 是否为空或 undefined（字符串）。
     * @param str 文本
     * @return 是否为空或 undefined
     */
    public static boolean isEmptyOrUndefined(@Nullable CharSequence str) {
        return isEmpty(str) || isNullOrUndefinedStr(str);
    }

    /**
     * 是否为空白或 undefined（字符串）。
     * @param str 文本
     * @return 是否为空白或 undefined
     */
    public static boolean isBlankOrUndefined(@Nullable CharSequence str) {
        return isBlank(str) || isNullOrUndefinedStr(str);
    }

    private static boolean isNullOrUndefinedStr(@NotNull CharSequence str) {
        String strString = str.toString().trim();
        return NULL.equals(strString) || "undefined".equals(strString);
    }

    /**
     * trim 处理（null 返回 null）。
     * @param str 原始文本
     * @return 去除首尾空白后的文本
     */
    public static @Nullable String trim(@Nullable CharSequence str) {
        return str == null ? null : trim(str, 0);
    }

    /**
     * trim 处理（null 返回空字符串）。
     * @param str 原始文本
     * @return 去除首尾空白后的文本
     */
    public static @NotNull String trimToEmpty(@Nullable CharSequence str) {
        return str == null ? EMPTY : trim(str);
    }

    /**
     * trim 处理（空结果返回 null）。
     * @param str 原始文本
     * @return trim 结果
     */
    public static @Nullable String trimToNull(@Nullable CharSequence str) {
        String trimStr = trim(str);
        return EMPTY.equals(trimStr) ? null : trimStr;
    }

    /**
     * trim 开头。
     * @param str 原始文本
     * @return 结果
     */
    public static @Nullable String trimStart(@Nullable CharSequence str) {
        return trim(str, -1);
    }

    /**
     * trim 结尾。
     * @param str 原始文本
     * @return 结果
     */
    public static @Nullable String trimEnd(@Nullable CharSequence str) {
        return trim(str, 1);
    }

    /**
     * trim 处理（mode 控制头尾）。
     * @param str 原始文本
     * @param mode -1 仅左侧，0 两侧，1 仅右侧
     * @return trim 结果
     */
    public static @Nullable String trim(@Nullable CharSequence str, int mode) {
        return trim(str, mode, ZaStrUtil::isBlankChar);
    }

    /**
     * trim 处理（自定义过滤规则）。
     * @param str 原始文本
     * @param mode -1 仅左侧，0 两侧，1 仅右侧
     * @param predicate 空白判断
     * @return trim 结果
     */
    public static @Nullable String trim(@Nullable CharSequence str, int mode, @Nullable Predicate<Character> predicate) {
        if (str == null) return null;
        Predicate<Character> tester = predicate == null ? ZaStrUtil::isBlankChar : predicate;
        int length = str.length();
        int start = 0;
        int end = length;
        if (mode <= 0) {
            while (start < end && tester.test(str.charAt(start))) {
                start++;
            }
        }
        if (mode >= 0) {
            while (start < end && tester.test(str.charAt(end - 1))) {
                end--;
            }
        }
        if (start <= 0 && end >= length) {
            return str.toString();
        }
        return str.toString().substring(start, end);
    }

    /**
     * 是否以指定字符开头。
     * @param str 原始文本
     * @param c 前缀字符
     * @return 是否匹配
     */
    public static boolean startWith(@Nullable CharSequence str, char c) {
        return !isEmpty(str) && c == str.charAt(0);
    }

    /**
     * 是否以指定前缀开头。
     * @param str 原始文本
     * @param prefix 前缀
     * @param ignoreCase 是否忽略大小写
     * @return 是否匹配
     */
    public static boolean startWith(@Nullable CharSequence str, @Nullable CharSequence prefix, boolean ignoreCase) {
        return startWith(str, prefix, ignoreCase, false);
    }

    /**
     * 是否以指定前缀开头（可忽略相等）。
     * @param str 原始文本
     * @param prefix 前缀
     * @param ignoreCase 是否忽略大小写
     * @param ignoreEquals 相等时是否视为不匹配
     * @return 是否匹配
     */
    public static boolean startWith(@Nullable CharSequence str, @Nullable CharSequence prefix, boolean ignoreCase, boolean ignoreEquals) {
        if (str != null && prefix != null) {
            if (prefix.length() > str.length()) return false;
            boolean isStartWith = str.toString().regionMatches(ignoreCase, 0, prefix.toString(), 0, prefix.length());
            if (!isStartWith) return false;
            return !ignoreEquals || !equals(str, prefix, ignoreCase);
        }
        return !ignoreEquals && str == null && prefix == null;
    }

    /**
     * 是否以指定前缀开头（区分大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 是否匹配
     */
    public static boolean startWith(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        return startWith(str, prefix, false);
    }

    /**
     * 是否以指定前缀开头（忽略相等）。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 是否匹配
     */
    public static boolean startWithIgnoreEquals(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        return startWith(str, prefix, false, true);
    }

    /**
     * 是否以指定前缀开头（忽略大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 是否匹配
     */
    public static boolean startWithIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        return startWith(str, prefix, true);
    }

    /**
     * 是否以任一前缀开头。
     * @param str 原始文本
     * @param prefixes 前缀列表
     * @return 是否匹配
     */
    public static boolean startWithAny(@Nullable CharSequence str, @Nullable CharSequence... prefixes) {
        if (isEmpty(str) || isArrayEmpty(prefixes)) return false;
        for (CharSequence prefix : prefixes) {
            if (startWith(str, prefix, false)) return true;
        }
        return false;
    }

    /**
     * 是否以任一前缀开头（忽略大小写）。
     * @param str 原始文本
     * @param prefixes 前缀列表
     * @return 是否匹配
     */
    public static boolean startWithAnyIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence... prefixes) {
        if (isEmpty(str) || isArrayEmpty(prefixes)) return false;
        for (CharSequence prefix : prefixes) {
            if (startWith(str, prefix, true)) return true;
        }
        return false;
    }

    /**
     * 是否以指定字符结尾。
     * @param str 原始文本
     * @param c 后缀字符
     * @return 是否匹配
     */
    public static boolean endWith(@Nullable CharSequence str, char c) {
        return !isEmpty(str) && c == str.charAt(str.length() - 1);
    }

    /**
     * 是否以指定后缀结尾。
     * @param str 原始文本
     * @param suffix 后缀
     * @param ignoreCase 是否忽略大小写
     * @return 是否匹配
     */
    public static boolean endWith(@Nullable CharSequence str, @Nullable CharSequence suffix, boolean ignoreCase) {
        return endWith(str, suffix, ignoreCase, false);
    }

    /**
     * 是否以指定后缀结尾（可忽略相等）。
     * @param str 原始文本
     * @param suffix 后缀
     * @param ignoreCase 是否忽略大小写
     * @param ignoreEquals 相等时是否视为不匹配
     * @return 是否匹配
     */
    public static boolean endWith(@Nullable CharSequence str, @Nullable CharSequence suffix, boolean ignoreCase, boolean ignoreEquals) {
        if (str != null && suffix != null) {
            int suffixLength = suffix.length();
            int strOffset = str.length() - suffixLength;
            if (strOffset < 0) return false;
            boolean isEndWith = str.toString().regionMatches(ignoreCase, strOffset, suffix.toString(), 0, suffixLength);
            if (!isEndWith) return false;
            return !ignoreEquals || !equals(str, suffix, ignoreCase);
        }
        return !ignoreEquals && str == null && suffix == null;
    }

    /**
     * 是否以指定后缀结尾（区分大小写）。
     * @param str 原始文本
     * @param suffix 后缀
     * @return 是否匹配
     */
    public static boolean endWith(@Nullable CharSequence str, @Nullable CharSequence suffix) {
        return endWith(str, suffix, false);
    }

    /**
     * 是否以指定后缀结尾（忽略大小写）。
     * @param str 原始文本
     * @param suffix 后缀
     * @return 是否匹配
     */
    public static boolean endWithIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence suffix) {
        return endWith(str, suffix, true);
    }

    /**
     * 是否以任一后缀结尾。
     * @param str 原始文本
     * @param suffixes 后缀列表
     * @return 是否匹配
     */
    public static boolean endWithAny(@Nullable CharSequence str, @Nullable CharSequence... suffixes) {
        if (isEmpty(str) || isArrayEmpty(suffixes)) return false;
        for (CharSequence suffix : suffixes) {
            if (endWith(str, suffix, false)) return true;
        }
        return false;
    }

    /**
     * 是否以任一后缀结尾（忽略大小写）。
     * @param str 原始文本
     * @param suffixes 后缀列表
     * @return 是否匹配
     */
    public static boolean endWithAnyIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence... suffixes) {
        if (isEmpty(str) || isArrayEmpty(suffixes)) return false;
        for (CharSequence suffix : suffixes) {
            if (endWith(str, suffix, true)) return true;
        }
        return false;
    }

    /**
     * 是否包含指定字符。
     * @param str 原始文本
     * @param searchChar 目标字符
     * @return 是否包含
     */
    public static boolean contains(@Nullable CharSequence str, char searchChar) {
        return indexOf(str, searchChar) > -1;
    }

    /**
     * 是否包含指定子串。
     * @param str 原始文本
     * @param searchStr 子串
     * @return 是否包含
     */
    public static boolean contains(@Nullable CharSequence str, @Nullable CharSequence searchStr) {
        return str != null && searchStr != null && str.toString().contains(searchStr);
    }

    /**
     * 是否包含任意子串。
     * @param str 原始文本
     * @param testStrs 子串列表
     * @return 是否包含
     */
    public static boolean containsAny(@Nullable CharSequence str, @Nullable CharSequence... testStrs) {
        return getContainsStr(str, testStrs) != null;
    }

    /**
     * 是否包含任意字符。
     * @param str 原始文本
     * @param testChars 字符列表
     * @return 是否包含
     */
    public static boolean containsAny(@Nullable CharSequence str, @Nullable char... testChars) {
        if (isEmpty(str) || isCharArrayEmpty(testChars)) return false;
        int len = str.length();
        for (int i = 0; i < len; i++) {
            if (containsChar(testChars, str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 是否仅包含给定字符集合。
     * @param str 原始文本
     * @param testChars 字符集合
     * @return 是否仅包含
     */
    public static boolean containsOnly(@Nullable CharSequence str, @Nullable char... testChars) {
        if (isEmpty(str) || isCharArrayEmpty(testChars)) return true;
        int len = str.length();
        for (int i = 0; i < len; i++) {
            if (!containsChar(testChars, str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 是否包含全部子串。
     * @param str 原始文本
     * @param testStrs 子串列表
     * @return 是否包含全部
     */
    public static boolean containsAll(@Nullable CharSequence str, @Nullable CharSequence... testStrs) {
        if (isBlank(str) || isArrayEmpty(testStrs)) return false;
        for (CharSequence testStr : testStrs) {
            if (!contains(str, testStr)) return false;
        }
        return true;
    }

    /**
     * 是否包含空白字符。
     * @param str 原始文本
     * @return 是否包含空白字符
     */
    public static boolean containsBlank(@Nullable CharSequence str) {
        if (str == null || str.length() == 0) return false;
        int length = str.length();
        for (int i = 0; i < length; i++) {
            if (isBlankChar(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取首个被包含的子串。
     * @param str 原始文本
     * @param testStrs 子串列表
     * @return 匹配子串，未匹配返回 null
     */
    public static @Nullable String getContainsStr(@Nullable CharSequence str, @Nullable CharSequence... testStrs) {
        if (isEmpty(str) || isArrayEmpty(testStrs)) return null;
        for (CharSequence checkStr : testStrs) {
            if (checkStr != null && str.toString().contains(checkStr)) {
                return checkStr.toString();
            }
        }
        return null;
    }

    /**
     * 是否包含子串（忽略大小写）。
     * @param str 原始文本
     * @param testStr 子串
     * @return 是否包含
     */
    public static boolean containsIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence testStr) {
        if (str == null) return testStr == null;
        return indexOfIgnoreCase(str, testStr) > -1;
    }

    /**
     * 是否包含任意子串（忽略大小写）。
     * @param str 原始文本
     * @param testStrs 子串列表
     * @return 是否包含
     */
    public static boolean containsAnyIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence... testStrs) {
        return getContainsStrIgnoreCase(str, testStrs) != null;
    }

    /**
     * 获取首个被包含的子串（忽略大小写）。
     * @param str 原始文本
     * @param testStrs 子串列表
     * @return 匹配子串，未匹配返回 null
     */
    public static @Nullable String getContainsStrIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence... testStrs) {
        if (isEmpty(str) || isArrayEmpty(testStrs)) return null;
        for (CharSequence testStr : testStrs) {
            if (containsIgnoreCase(str, testStr)) {
                return testStr == null ? null : testStr.toString();
            }
        }
        return null;
    }

    /**
     * 查找字符首次出现的位置。
     * @param str 原始文本
     * @param searchChar 目标字符
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOf(@Nullable CharSequence str, char searchChar) {
        return indexOf(str, searchChar, 0);
    }

    /**
     * 查找字符首次出现的位置。
     * @param str 原始文本
     * @param searchChar 目标字符
     * @param start 起始位置
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOf(@Nullable CharSequence str, char searchChar, int start) {
        return indexOf(str, searchChar, start, -1);
    }

    /**
     * 查找字符首次出现的位置。
     * @param text 原始文本
     * @param searchChar 目标字符
     * @param start 起始位置
     * @param end 结束位置（不包含，-1 表示到末尾）
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOf(@Nullable CharSequence text, char searchChar, int start, int end) {
        if (isEmpty(text)) return INDEX_NOT_FOUND;
        int len = text.length();
        int from = Math.max(0, start);
        int to = end < 0 || end > len ? len : end;
        for (int i = from; i < to; i++) {
            if (text.charAt(i) == searchChar) return i;
        }
        return INDEX_NOT_FOUND;
    }

    /**
     * 查找子串位置（忽略大小写）。
     * @param str 原始文本
     * @param searchStr 子串
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOfIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence searchStr) {
        return indexOfIgnoreCase(str, searchStr, 0);
    }

    /**
     * 查找子串位置（区分大小写）。
     * @param str 原始文本
     * @param searchStr 子串
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOf(@Nullable CharSequence str, @Nullable CharSequence searchStr) {
        return indexOf(str, searchStr, 0, false);
    }

    /**
     * 查找子串位置（区分大小写）。
     * @param str 原始文本
     * @param searchStr 子串
     * @param fromIndex 起始位置
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOf(@Nullable CharSequence str, @Nullable CharSequence searchStr, int fromIndex) {
        return indexOf(str, searchStr, fromIndex, false);
    }

    /**
     * 查找子串位置（忽略大小写）。
     * @param str 原始文本
     * @param searchStr 子串
     * @param fromIndex 起始位置
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOfIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence searchStr, int fromIndex) {
        return indexOf(str, searchStr, fromIndex, true);
    }

    /**
     * 查找子串位置。
     * @param text 原始文本
     * @param searchStr 子串
     * @param from 起始位置
     * @param ignoreCase 是否忽略大小写
     * @return 索引位置，未找到返回 -1
     */
    public static int indexOf(@Nullable CharSequence text, @Nullable CharSequence searchStr, int from, boolean ignoreCase) {
        if (isEmpty(text) || isEmpty(searchStr)) {
            return equals(text, searchStr) ? 0 : INDEX_NOT_FOUND;
        }
        String textStr = text.toString();
        String search = searchStr.toString();
        int textLen = textStr.length();
        int searchLen = search.length();
        if (from < 0) from = 0;
        int max = textLen - searchLen;
        if (max < from) return INDEX_NOT_FOUND;
        for (int i = from; i <= max; i++) {
            if (textStr.regionMatches(ignoreCase, i, search, 0, searchLen)) {
                return i;
            }
        }
        return INDEX_NOT_FOUND;
    }

    /**
     * 从后向前查找子串（忽略大小写）。
     * @param str 原始文本
     * @param searchStr 子串
     * @return 索引位置，未找到返回 -1
     */
    public static int lastIndexOfIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence searchStr) {
        if (str == null) return INDEX_NOT_FOUND;
        return lastIndexOfIgnoreCase(str, searchStr, str.length());
    }

    /**
     * 从后向前查找子串（忽略大小写）。
     * @param str 原始文本
     * @param searchStr 子串
     * @param fromIndex 起始位置
     * @return 索引位置，未找到返回 -1
     */
    public static int lastIndexOfIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence searchStr, int fromIndex) {
        return lastIndexOf(str, searchStr, fromIndex, true);
    }

    /**
     * 从后向前查找子串。
     * @param text 原始文本
     * @param searchStr 子串
     * @param from 起始位置
     * @param ignoreCase 是否忽略大小写
     * @return 索引位置，未找到返回 -1
     */
    public static int lastIndexOf(@Nullable CharSequence text, @Nullable CharSequence searchStr, int from, boolean ignoreCase) {
        if (isEmpty(text) || isEmpty(searchStr)) {
            return equals(text, searchStr) ? 0 : INDEX_NOT_FOUND;
        }
        String textStr = text.toString();
        String search = searchStr.toString();
        int textLen = textStr.length();
        int searchLen = search.length();
        if (searchLen == 0) return INDEX_NOT_FOUND;
        int fromIndex = Math.min(from, textLen - searchLen);
        if (fromIndex < 0) return INDEX_NOT_FOUND;
        for (int i = fromIndex; i >= 0; i--) {
            if (textStr.regionMatches(ignoreCase, i, search, 0, searchLen)) {
                return i;
            }
        }
        return INDEX_NOT_FOUND;
    }

    /**
     * 获取第 n 次出现的位置。
     * @param str 原始文本
     * @param searchStr 子串
     * @param ordinal 次序（从 1 开始）
     * @return 索引位置，未找到返回 -1
     */
    public static int ordinalIndexOf(@Nullable CharSequence str, @Nullable CharSequence searchStr, int ordinal) {
        if (str == null || searchStr == null || ordinal <= 0) return INDEX_NOT_FOUND;
        if (searchStr.length() == 0) return 0;
        int found = 0;
        int index = INDEX_NOT_FOUND;
        do {
            index = indexOf(str, searchStr, index + 1, false);
            if (index < 0) return index;
            found++;
        } while (found < ordinal);
        return index;
    }

    /**
     * 删除全部匹配的子串。
     * @param str 原始文本
     * @param strToRemove 待删除子串
     * @return 结果文本
     */
    public static @Nullable String removeAll(@Nullable CharSequence str, @Nullable CharSequence strToRemove) {
        if (!isEmpty(str) && !isEmpty(strToRemove)) {
            return str.toString().replace(strToRemove, EMPTY);
        }
        return str(str);
    }

    /**
     * 删除多个子串。
     * @param str 原始文本
     * @param strsToRemove 待删除子串列表
     * @return 结果文本
     */
    public static @Nullable String removeAny(@Nullable CharSequence str, @Nullable CharSequence... strsToRemove) {
        String result = str(str);
        if (isNotEmpty(str) && !isArrayEmpty(strsToRemove)) {
            for (CharSequence strToRemove : strsToRemove) {
                result = removeAll(result, strToRemove);
            }
        }
        return result;
    }

    /**
     * 删除指定字符集合。
     * @param str 原始文本
     * @param chars 待删除字符
     * @return 结果文本
     */
    public static @Nullable String removeAll(@Nullable CharSequence str, @Nullable char... chars) {
        if (str == null) return null;
        if (isCharArrayEmpty(chars)) return str(str);
        int len = str.length();
        if (len == 0) return str(str);
        StringBuilder builder = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = str.charAt(i);
            if (!containsChar(chars, c)) {
                builder.append(c);
            }
        }
        return builder.toString();
    }

    /**
     * 删除所有换行符。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String removeAllLineBreaks(@Nullable CharSequence str) {
        return removeAll(str, '\r', '\n');
    }

    /**
     * 移除前缀后将首字符转小写。
     * @param str 原始文本
     * @param preLength 前缀长度
     * @return 结果文本
     */
    public static @Nullable String removePreAndLowerFirst(@Nullable CharSequence str, int preLength) {
        if (str == null) return null;
        String text = str.toString();
        if (text.length() > preLength) {
            char first = Character.toLowerCase(text.charAt(preLength));
            return text.length() > preLength + 1
                    ? String.format("%c%s", first, text.substring(preLength + 1))
                    : String.valueOf(first);
        }
        return text;
    }

    /**
     * 移除前缀后将首字符转小写。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 结果文本
     */
    public static @Nullable String removePreAndLowerFirst(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        return lowerFirst(removePrefix(str, prefix));
    }

    /**
     * 移除前缀（区分大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 结果文本
     */
    public static @Nullable String removePrefix(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        if (!isEmpty(str) && !isEmpty(prefix)) {
            String str2 = str.toString();
            return str2.startsWith(prefix.toString()) ? subSuf(str2, prefix.length()) : str2;
        }
        return str(str);
    }

    /**
     * 移除前缀（忽略大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 结果文本
     */
    public static @Nullable String removePrefixIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        if (!isEmpty(str) && !isEmpty(prefix)) {
            String str2 = str.toString();
            return startWithIgnoreCase(str, prefix) ? subSuf(str2, prefix.length()) : str2;
        }
        return str(str);
    }

    /**
     * 移除后缀（区分大小写）。
     * @param str 原始文本
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String removeSuffix(@Nullable CharSequence str, @Nullable CharSequence suffix) {
        if (!isEmpty(str) && !isEmpty(suffix)) {
            String str2 = str.toString();
            return str2.endsWith(suffix.toString()) ? subPre(str2, str2.length() - suffix.length()) : str2;
        }
        return str(str);
    }

    /**
     * 移除后缀后将首字符转小写。
     * @param str 原始文本
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String removeSufAndLowerFirst(@Nullable CharSequence str, @Nullable CharSequence suffix) {
        return lowerFirst(removeSuffix(str, suffix));
    }

    /**
     * 移除后缀（忽略大小写）。
     * @param str 原始文本
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String removeSuffixIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence suffix) {
        if (!isEmpty(str) && !isEmpty(suffix)) {
            String str2 = str.toString();
            return endWithIgnoreCase(str, suffix) ? subPre(str2, str2.length() - suffix.length()) : str2;
        }
        return str(str);
    }

    /**
     * 删除所有空白字符。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String cleanBlank(@Nullable CharSequence str) {
        return filter(str, c -> !isBlankChar(c));
    }

    /**
     * 去除指定前后缀（区分大小写）。
     * @param str 原始文本
     * @param prefixOrSuffix 前后缀
     * @return 结果文本
     */
    public static @Nullable String strip(@Nullable CharSequence str, @Nullable CharSequence prefixOrSuffix) {
        return equals(str, prefixOrSuffix) ? EMPTY : strip(str, prefixOrSuffix, prefixOrSuffix);
    }

    /**
     * 去除指定前后缀（区分大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String strip(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence suffix) {
        if (isEmpty(str)) return str(str);
        int from = 0;
        int to = str.length();
        String str2 = str.toString();
        if (startWith(str2, prefix)) {
            from = prefix.length();
        }
        if (endWith(str2, suffix)) {
            to -= suffix.length();
        }
        return str2.substring(Math.min(from, to), Math.max(from, to));
    }

    /**
     * 去除指定前后缀（忽略大小写）。
     * @param str 原始文本
     * @param prefixOrSuffix 前后缀
     * @return 结果文本
     */
    public static @Nullable String stripIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence prefixOrSuffix) {
        return stripIgnoreCase(str, prefixOrSuffix, prefixOrSuffix);
    }

    /**
     * 去除指定前后缀（忽略大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String stripIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence suffix) {
        if (isEmpty(str)) return str(str);
        int from = 0;
        int to = str.length();
        String str2 = str.toString();
        if (startWithIgnoreCase(str2, prefix)) {
            from = prefix.length();
        }
        if (endWithIgnoreCase(str2, suffix)) {
            to -= suffix.length();
        }
        return str2.substring(from, to);
    }

    /**
     * 如缺失则添加前缀。
     * @param str 原始文本
     * @param prefix 前缀
     * @return 结果文本
     */
    public static @Nullable String addPrefixIfNot(@Nullable CharSequence str, @Nullable CharSequence prefix) {
        return prependIfMissing(str, prefix, prefix);
    }

    /**
     * 如缺失则添加后缀。
     * @param str 原始文本
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String addSuffixIfNot(@Nullable CharSequence str, @Nullable CharSequence suffix) {
        return appendIfMissing(str, suffix, suffix);
    }

    /**
     * 按分隔符切分并转为 long 数组（trim + 忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @return long 数组
     */
    public static long[] splitToLong(@Nullable CharSequence str, char separator) {
        List<String> list = splitTrim(str, separator);
        long[] result = new long[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = Long.parseLong(list.get(i));
        }
        return result;
    }

    /**
     * 按分隔符切分并转为 long 数组（trim + 忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @return long 数组
     */
    public static long[] splitToLong(@Nullable CharSequence str, @Nullable CharSequence separator) {
        List<String> list = splitTrim(str, separator);
        long[] result = new long[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = Long.parseLong(list.get(i));
        }
        return result;
    }

    /**
     * 按分隔符切分并转为 int 数组（trim + 忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @return int 数组
     */
    public static int[] splitToInt(@Nullable CharSequence str, char separator) {
        List<String> list = splitTrim(str, separator);
        int[] result = new int[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = Integer.parseInt(list.get(i));
        }
        return result;
    }

    /**
     * 按分隔符切分并转为 int 数组（trim + 忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @return int 数组
     */
    public static int[] splitToInt(@Nullable CharSequence str, @Nullable CharSequence separator) {
        List<String> list = splitTrim(str, separator);
        int[] result = new int[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = Integer.parseInt(list.get(i));
        }
        return result;
    }

    /**
     * 按字符切分。
     * @param str 原始文本
     * @param separator 分隔符
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, char separator) {
        return split(str, separator, 0);
    }

    /**
     * 按字符串切分为数组。
     * @param str 原始文本
     * @param separator 分隔符
     * @return 切分结果数组
     */
    public static @NotNull String[] splitToArray(@Nullable CharSequence str, @Nullable CharSequence separator) {
        if (str == null) return new String[0];
        List<String> list = split(str, separator, 0, false, false);
        return list.toArray(new String[0]);
    }

    /**
     * 按字符切分为数组。
     * @param str 原始文本
     * @param separator 分隔符
     * @return 切分结果数组
     */
    public static @NotNull String[] splitToArray(@Nullable CharSequence str, char separator) {
        return splitToArray(str, separator, 0);
    }

    /**
     * 按字符切分为数组（带 limit）。
     * @param text 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @return 切分结果数组
     */
    public static @NotNull String[] splitToArray(@Nullable CharSequence text, char separator, int limit) {
        if (text == null) {
            throw new IllegalArgumentException("Text must be not null!");
        }
        List<String> list = split(text, separator, limit, false, false);
        return list.toArray(new String[0]);
    }

    /**
     * 按字符切分。
     * @param str 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, char separator, int limit) {
        return split(str, separator, limit, false, false);
    }

    /**
     * 按字符切分并 trim。
     * @param str 原始文本
     * @param separator 分隔符
     * @return 切分结果
     */
    public static @NotNull List<String> splitTrim(@Nullable CharSequence str, char separator) {
        return splitTrim(str, separator, -1);
    }

    /**
     * 按字符串切分并 trim。
     * @param str 原始文本
     * @param separator 分隔符
     * @return 切分结果
     */
    public static @NotNull List<String> splitTrim(@Nullable CharSequence str, @Nullable CharSequence separator) {
        return splitTrim(str, separator, -1);
    }

    /**
     * 按字符切分并 trim。
     * @param str 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @return 切分结果
     */
    public static @NotNull List<String> splitTrim(@Nullable CharSequence str, char separator, int limit) {
        return split(str, separator, limit, true, true);
    }

    /**
     * 按字符串切分并 trim。
     * @param str 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @return 切分结果
     */
    public static @NotNull List<String> splitTrim(@Nullable CharSequence str, @Nullable CharSequence separator, int limit) {
        return split(str, separator, limit, true, true);
    }

    /**
     * 按字符切分（可 trim/忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @param isTrim 是否 trim
     * @param ignoreEmpty 是否忽略空段
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, char separator, boolean isTrim, boolean ignoreEmpty) {
        return split(str, separator, 0, isTrim, ignoreEmpty);
    }

    /**
     * 按字符切分（可 limit/trim/忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @param isTrim 是否 trim
     * @param ignoreEmpty 是否忽略空段
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, char separator, int limit, boolean isTrim, boolean ignoreEmpty) {
        List<String> result = new ArrayList<>();
        if (str == null) return result;
        String text = str.toString();
        if (limit == 1) {
            addSplitPart(result, text, isTrim, ignoreEmpty);
            return result;
        }
        int len = text.length();
        int start = 0;
        int count = 0;
        for (int i = 0; i < len; i++) {
            if (text.charAt(i) == separator && (limit <= 0 || count < limit - 1)) {
                addSplitPart(result, text.substring(start, i), isTrim, ignoreEmpty);
                start = i + 1;
                count++;
            }
        }
        addSplitPart(result, text.substring(start), isTrim, ignoreEmpty);
        return result;
    }

    /**
     * 按字符切分并映射。
     * @param str 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @param ignoreEmpty 是否忽略空段
     * @param mapping 映射函数
     * @param <R> 结果类型
     * @return 映射结果
     */
    public static <R> @NotNull List<R> split(@Nullable CharSequence str, char separator, int limit, boolean ignoreEmpty, @Nullable Function<String, R> mapping) {
        List<R> result = new ArrayList<>();
        if (mapping == null) return result;
        List<String> parts = split(str, separator, limit, false, ignoreEmpty);
        for (String part : parts) {
            result.add(mapping.apply(part));
        }
        return result;
    }

    /**
     * 按字符串切分。
     * @param str 原始文本
     * @param separator 分隔符
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, @Nullable CharSequence separator) {
        return split(str, separator, false, false);
    }

    /**
     * 按字符串切分（可 trim/忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @param isTrim 是否 trim
     * @param ignoreEmpty 是否忽略空段
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, @Nullable CharSequence separator, boolean isTrim, boolean ignoreEmpty) {
        return split(str, separator, 0, isTrim, ignoreEmpty);
    }

    /**
     * 按字符串切分（可 limit/trim/忽略空段）。
     * @param str 原始文本
     * @param separator 分隔符
     * @param limit 最大切分数
     * @param isTrim 是否 trim
     * @param ignoreEmpty 是否忽略空段
     * @return 切分结果
     */
    public static @NotNull List<String> split(@Nullable CharSequence str, @Nullable CharSequence separator, int limit, boolean isTrim, boolean ignoreEmpty) {
        List<String> result = new ArrayList<>();
        if (str == null) return result;
        String text = str.toString();
        String sep = separator == null ? null : separator.toString();
        if (sep == null || sep.isEmpty()) {
            addSplitPart(result, text, isTrim, ignoreEmpty);
            return result;
        }
        if (limit == 1) {
            addSplitPart(result, text, isTrim, ignoreEmpty);
            return result;
        }
        int fromIndex = 0;
        int count = 0;
        int index = text.indexOf(sep, fromIndex);
        while (index >= 0 && (limit <= 0 || count < limit - 1)) {
            addSplitPart(result, text.substring(fromIndex, index), isTrim, ignoreEmpty);
            fromIndex = index + sep.length();
            count++;
            index = text.indexOf(sep, fromIndex);
        }
        addSplitPart(result, text.substring(fromIndex), isTrim, ignoreEmpty);
        return result;
    }

    /**
     * 按固定长度切分为数组。
     * @param str 原始文本
     * @param len 每段长度
     * @return 切分数组
     */
    public static @Nullable String[] split(@Nullable CharSequence str, int len) {
        if (str == null) return null;
        String text = str.toString();
        if (len <= 0) return new String[]{text};
        int strLen = text.length();
        int part = (strLen + len - 1) / len;
        String[] array = new String[part];
        for (int i = 0; i < part; i++) {
            int start = i * len;
            int end = Math.min(start + len, strLen);
            array[i] = text.substring(start, end);
        }
        return array;
    }

    /**
     * 按固定长度切分（不足一段保留原串）。
     * @param str 原始文本
     * @param partLength 段长度
     * @return 切分数组
     */
    public static @Nullable String[] cut(@Nullable CharSequence str, int partLength) {
        if (str == null) return null;
        String text = str.toString();
        int len = text.length();
        if (len < partLength || partLength <= 0) {
            return new String[]{text};
        }
        int part = (len + partLength - 1) / partLength;
        String[] array = new String[part];
        for (int i = 0; i < part; i++) {
            int start = i * partLength;
            int end = i == part - 1 ? len : start + partLength;
            array[i] = text.substring(start, end);
        }
        return array;
    }

    /**
     * 子串截取（支持负索引）。
     * @param str 原始文本
     * @param fromIndexInclude 起始位置（含）
     * @param toIndexExclude 结束位置（不含）
     * @return 截取结果
     */
    public static @Nullable String sub(@Nullable CharSequence str, int fromIndexInclude, int toIndexExclude) {
        if (isEmpty(str)) return str(str);
        int len = str.length();
        if (fromIndexInclude < 0) {
            fromIndexInclude += len;
            if (fromIndexInclude < 0) {
                fromIndexInclude = 0;
            }
        } else if (fromIndexInclude > len) {
            fromIndexInclude = len;
        }
        if (toIndexExclude < 0) {
            toIndexExclude += len;
            if (toIndexExclude < 0) {
                toIndexExclude = len;
            }
        } else if (toIndexExclude > len) {
            toIndexExclude = len;
        }
        if (toIndexExclude < fromIndexInclude) {
            int tmp = fromIndexInclude;
            fromIndexInclude = toIndexExclude;
            toIndexExclude = tmp;
        }
        return fromIndexInclude == toIndexExclude ? EMPTY : str.toString().substring(fromIndexInclude, toIndexExclude);
    }

    /**
     * 按 code point 截取。
     * @param str 原始文本
     * @param fromIndex 起始位置
     * @param toIndex 结束位置
     * @return 截取结果
     */
    public static @Nullable String subByCodePoint(@Nullable CharSequence str, int fromIndex, int toIndex) {
        if (isEmpty(str)) return str(str);
        if (fromIndex < 0 || fromIndex > toIndex) {
            throw new IllegalArgumentException();
        }
        if (fromIndex == toIndex) return EMPTY;
        StringBuilder sb = new StringBuilder();
        int subLen = toIndex - fromIndex;
        str.toString().codePoints().skip(fromIndex).limit(subLen).forEach(v -> sb.append(Character.toChars(v)));
        return sb.toString();
    }

    /**
     * 按 GBK 截取前缀。
     * @param str 原始文本
     * @param len 字节长度
     * @param suffix 追加后缀
     * @return 截取结果
     */
    public static @Nullable String subPreGbk(@Nullable CharSequence str, int len, @Nullable CharSequence suffix) {
        return String.format("%s%s", subPreGbk(str, len, true), suffix);
    }

    /**
     * 按 GBK 截取前缀。
     * @param str 原始文本
     * @param len 字节长度
     * @param halfUp 单字节修正方向
     * @return 截取结果
     */
    public static @Nullable String subPreGbk(@Nullable CharSequence str, int len, boolean halfUp) {
        if (isEmpty(str)) return str(str);
        Charset gbk = Charset.forName("GBK");
        byte[] b = bytes(str, gbk);
        if (b.length <= len) {
            return str.toString();
        }
        int counterOfDoubleByte = 0;
        for (int i = 0; i < len; i++) {
            if (b[i] < 0) {
                counterOfDoubleByte++;
            }
        }
        if (counterOfDoubleByte % 2 != 0) {
            if (halfUp) {
                len++;
            } else {
                len--;
            }
        }
        return new String(b, 0, len, gbk);
    }

    /**
     * 截取前缀。
     * @param string 原始文本
     * @param toIndexExclude 结束位置（不含）
     * @return 截取结果
     */
    public static @Nullable String subPre(@Nullable CharSequence string, int toIndexExclude) {
        return sub(string, 0, toIndexExclude);
    }

    /**
     * 截取后缀。
     * @param string 原始文本
     * @param fromIndex 起始位置
     * @return 截取结果
     */
    public static @Nullable String subSuf(@Nullable CharSequence string, int fromIndex) {
        return isEmpty(string) ? null : sub(string, fromIndex, string.length());
    }

    /**
     * 按长度截取后缀。
     * @param string 原始文本
     * @param length 长度
     * @return 截取结果
     */
    public static @Nullable String subSufByLength(@Nullable CharSequence string, int length) {
        if (isEmpty(string)) return null;
        return length <= 0 ? EMPTY : sub(string, -length, string.length());
    }

    /**
     * 按起点和长度截取。
     * @param input 原始文本
     * @param fromIndex 起始位置
     * @param length 长度
     * @return 截取结果
     */
    public static @Nullable String subWithLength(@Nullable String input, int fromIndex, int length) {
        int toIndex = fromIndex < 0 ? fromIndex - length : fromIndex + length;
        return sub(input, fromIndex, toIndex);
    }

    /**
     * 截取分隔符之前的子串。
     * @param string 原始文本
     * @param separator 分隔符
     * @param isLastSeparator 是否取最后一个分隔符
     * @return 截取结果
     */
    public static @Nullable String subBefore(@Nullable CharSequence string, @Nullable CharSequence separator, boolean isLastSeparator) {
        if (!isEmpty(string) && separator != null) {
            String str = string.toString();
            String sep = separator.toString();
            if (sep.isEmpty()) {
                return EMPTY;
            }
            int pos = isLastSeparator ? str.lastIndexOf(sep) : str.indexOf(sep);
            if (pos == -1) {
                return str;
            }
            return pos == 0 ? EMPTY : str.substring(0, pos);
        }
        return string == null ? null : string.toString();
    }

    /**
     * 截取分隔符之前的子串。
     * @param string 原始文本
     * @param separator 分隔符
     * @param isLastSeparator 是否取最后一个分隔符
     * @return 截取结果
     */
    public static @Nullable String subBefore(@Nullable CharSequence string, char separator, boolean isLastSeparator) {
        if (isEmpty(string)) return string == null ? null : EMPTY;
        String str = string.toString();
        int pos = isLastSeparator ? str.lastIndexOf(separator) : str.indexOf(separator);
        if (pos == -1) {
            return str;
        }
        return pos == 0 ? EMPTY : str.substring(0, pos);
    }

    /**
     * 截取分隔符之后的子串。
     * @param string 原始文本
     * @param separator 分隔符
     * @param isLastSeparator 是否取最后一个分隔符
     * @return 截取结果
     */
    public static @Nullable String subAfter(@Nullable CharSequence string, @Nullable CharSequence separator, boolean isLastSeparator) {
        if (isEmpty(string)) return string == null ? null : EMPTY;
        if (separator == null) return EMPTY;
        String str = string.toString();
        String sep = separator.toString();
        int pos = isLastSeparator ? str.lastIndexOf(sep) : str.indexOf(sep);
        return pos != -1 && string.length() - 1 != pos ? str.substring(pos + separator.length()) : EMPTY;
    }

    /**
     * 截取分隔符之后的子串。
     * @param string 原始文本
     * @param separator 分隔符
     * @param isLastSeparator 是否取最后一个分隔符
     * @return 截取结果
     */
    public static @Nullable String subAfter(@Nullable CharSequence string, char separator, boolean isLastSeparator) {
        if (isEmpty(string)) return string == null ? null : EMPTY;
        String str = string.toString();
        int pos = isLastSeparator ? str.lastIndexOf(separator) : str.indexOf(separator);
        return pos == -1 ? EMPTY : str.substring(pos + 1);
    }

    /**
     * 截取两个标记之间的子串。
     * @param str 原始文本
     * @param before 开始标记
     * @param after 结束标记
     * @return 截取结果，未匹配返回 null
     */
    public static @Nullable String subBetween(@Nullable CharSequence str, @Nullable CharSequence before, @Nullable CharSequence after) {
        if (str == null || before == null || after == null) return null;
        String str2 = str.toString();
        String before2 = before.toString();
        String after2 = after.toString();
        int start = str2.indexOf(before2);
        if (start != -1) {
            int end = str2.indexOf(after2, start + before2.length());
            if (end != -1) {
                return str2.substring(start + before2.length(), end);
            }
        }
        return null;
    }

    /**
     * 截取两个标记之间的子串。
     * @param str 原始文本
     * @param beforeAndAfter 统一标记
     * @return 截取结果
     */
    public static @Nullable String subBetween(@Nullable CharSequence str, @Nullable CharSequence beforeAndAfter) {
        return subBetween(str, beforeAndAfter, beforeAndAfter);
    }

    /**
     * 批量截取标记之间的子串。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 截取结果数组
     */
    public static @NotNull String[] subBetweenAll(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence suffix) {
        if (hasEmpty(str, prefix, suffix) || !contains(str, prefix)) {
            return new String[0];
        }
        List<String> result = new ArrayList<>();
        String prefixStr = prefix.toString();
        String suffixStr = suffix.toString();
        String[] split = splitToArray(str, prefixStr);
        if (prefixStr.equals(suffixStr)) {
            for (int i = 1; i < split.length; i += 2) {
                result.add(split[i]);
            }
        } else {
            for (int i = 1; i < split.length; i++) {
                String fragment = split[i];
                int suffixIndex = fragment.indexOf(suffixStr);
                if (suffixIndex > 0) {
                    result.add(fragment.substring(0, suffixIndex));
                }
            }
        }
        return result.toArray(new String[0]);
    }

    /**
     * 批量截取标记之间的子串。
     * @param str 原始文本
     * @param prefixAndSuffix 前后缀
     * @return 截取结果数组
     */
    public static @NotNull String[] subBetweenAll(@Nullable CharSequence str, @Nullable CharSequence prefixAndSuffix) {
        return subBetweenAll(str, prefixAndSuffix, prefixAndSuffix);
    }

    /**
     * 重复字符。
     * @param c 字符
     * @param count 次数
     * @return 结果文本
     */
    public static @NotNull String repeat(char c, int count) {
        if (count <= 0) return EMPTY;
        char[] result = new char[count];
        for (int i = 0; i < count; i++) {
            result[i] = c;
        }
        return new String(result);
    }

    /**
     * 重复字符串。
     * @param str 原始文本
     * @param count 次数
     * @return 结果文本
     */
    public static @Nullable String repeat(@Nullable CharSequence str, int count) {
        if (str == null) return null;
        if (count <= 0 || str.length() == 0) return EMPTY;
        if (count == 1) return str.toString();
        int len = str.length();
        long longSize = (long) len * (long) count;
        int size = (int) longSize;
        if ((long) size != longSize) {
            throw new ArrayIndexOutOfBoundsException(String.format("Required String length is too large: %s", longSize));
        }
        char[] array = new char[size];
        str.toString().getChars(0, len, array, 0);
        int n;
        for (n = len; n < size - n; n <<= 1) {
            System.arraycopy(array, 0, array, n, n);
        }
        System.arraycopy(array, 0, array, n, size - n);
        return new String(array);
    }

    /**
     * 重复字符串到指定长度。
     * @param str 原始文本
     * @param padLen 目标长度
     * @return 结果文本
     */
    public static @Nullable String repeatByLength(@Nullable CharSequence str, int padLen) {
        if (str == null) return null;
        if (padLen <= 0) return EMPTY;
        int strLen = str.length();
        if (strLen == padLen) return str.toString();
        if (strLen > padLen) return subPre(str, padLen);
        char[] padding = new char[padLen];
        for (int i = 0; i < padLen; i++) {
            padding[i] = str.charAt(i % strLen);
        }
        return new String(padding);
    }

    /**
     * 重复并拼接。
     * @param str 原始文本
     * @param count 次数
     * @param delimiter 分隔符
     * @return 结果文本
     */
    public static @NotNull String repeatAndJoin(@Nullable CharSequence str, int count, @Nullable CharSequence delimiter) {
        if (count <= 0) return EMPTY;
        String text = str == null ? EMPTY : str.toString();
        StringBuilder builder = new StringBuilder(text.length() * count);
        builder.append(text);
        count--;
        boolean isAppendDelimiter = isNotEmpty(delimiter);
        while (count-- > 0) {
            if (isAppendDelimiter) {
                builder.append(delimiter);
            }
            builder.append(text);
        }
        return builder.toString();
    }

    /**
     * 比较字符串是否相等（区分大小写）。
     * @param str1 文本1
     * @param str2 文本2
     * @return 是否相等
     */
    public static boolean equals(@Nullable CharSequence str1, @Nullable CharSequence str2) {
        return equals(str1, str2, false);
    }

    /**
     * 比较字符串是否相等（忽略大小写）。
     * @param str1 文本1
     * @param str2 文本2
     * @return 是否相等
     */
    public static boolean equalsIgnoreCase(@Nullable CharSequence str1, @Nullable CharSequence str2) {
        return equals(str1, str2, true);
    }

    /**
     * 比较字符串是否相等。
     * @param str1 文本1
     * @param str2 文本2
     * @param ignoreCase 是否忽略大小写
     * @return 是否相等
     */
    public static boolean equals(@Nullable CharSequence str1, @Nullable CharSequence str2, boolean ignoreCase) {
        if (str1 == null) return str2 == null;
        if (str2 == null) return false;
        return ignoreCase ? str1.toString().equalsIgnoreCase(str2.toString()) : str1.toString().contentEquals(str2);
    }

    /**
     * 是否与任意文本相等（忽略大小写）。
     * @param str1 文本
     * @param strs 候选文本
     * @return 是否匹配
     */
    public static boolean equalsAnyIgnoreCase(@Nullable CharSequence str1, @Nullable CharSequence... strs) {
        return equalsAny(str1, true, strs);
    }

    /**
     * 是否与任意文本相等。
     * @param str1 文本
     * @param strs 候选文本
     * @return 是否匹配
     */
    public static boolean equalsAny(@Nullable CharSequence str1, @Nullable CharSequence... strs) {
        return equalsAny(str1, false, strs);
    }

    /**
     * 是否与任意文本相等。
     * @param str1 文本
     * @param ignoreCase 是否忽略大小写
     * @param strs 候选文本
     * @return 是否匹配
     */
    public static boolean equalsAny(@Nullable CharSequence str1, boolean ignoreCase, @Nullable CharSequence... strs) {
        if (isArrayEmpty(strs)) return false;
        for (CharSequence str : strs) {
            if (equals(str1, str, ignoreCase)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 指定位置字符是否匹配。
     * @param str 原始文本
     * @param position 位置
     * @param c 目标字符
     * @return 是否匹配
     */
    public static boolean equalsCharAt(@Nullable CharSequence str, int position, char c) {
        return str != null && position >= 0 && str.length() > position && c == str.charAt(position);
    }

    /**
     * 子串比较。
     * @param str1 文本1
     * @param start1 起点1
     * @param str2 文本2
     * @param ignoreCase 是否忽略大小写
     * @return 是否匹配
     */
    public static boolean isSubEquals(@Nullable CharSequence str1, int start1, @Nullable CharSequence str2, boolean ignoreCase) {
        return isSubEquals(str1, start1, str2, 0, str2 == null ? 0 : str2.length(), ignoreCase);
    }

    /**
     * 子串比较。
     * @param str1 文本1
     * @param start1 起点1
     * @param str2 文本2
     * @param start2 起点2
     * @param length 比较长度
     * @param ignoreCase 是否忽略大小写
     * @return 是否匹配
     */
    public static boolean isSubEquals(@Nullable CharSequence str1, int start1, @Nullable CharSequence str2, int start2, int length, boolean ignoreCase) {
        return str1 != null && str2 != null && str1.toString().regionMatches(ignoreCase, start1, str2.toString(), start2, length);
    }

    /**
     * 轻量格式化（{} 占位）。
     * @param template 模板
     * @param params 参数
     * @return 格式化结果
     */
    public static @NotNull String format(@Nullable CharSequence template, @Nullable Object... params) {
        if (template == null) return NULL;
        if (isArrayEmpty(params) || isBlank(template)) return template.toString();
        String text = template.toString();
        StringBuilder sb = new StringBuilder(text.length() + 16);
        int idx = 0;
        int paramIndex = 0;
        while (true) {
            int pos = text.indexOf("{}", idx);
            if (pos < 0) break;
            sb.append(text, idx, pos);
            if (paramIndex < params.length) {
                sb.append(String.valueOf(params[paramIndex++]));
            } else {
                sb.append("{}");
            }
            idx = pos + 2;
        }
        sb.append(text.substring(idx));
        return sb.toString();
    }

    /**
     * MessageFormat 格式化。
     * @param pattern 模板
     * @param arguments 参数
     * @return 格式化结果
     */
    public static @Nullable String indexedFormat(@Nullable CharSequence pattern, @Nullable Object... arguments) {
        return pattern == null ? null : MessageFormat.format(pattern.toString(), arguments);
    }

    /**
     * 获取 UTF-8 字节数组。
     * @param str 文本
     * @return 字节数组
     */
    public static byte[] utf8Bytes(@Nullable CharSequence str) {
        return bytes(str, StandardCharsets.UTF_8);
    }

    /**
     * 获取默认编码字节数组。
     * @param str 文本
     * @return 字节数组
     */
    public static byte[] bytes(@Nullable CharSequence str) {
        return bytes(str, Charset.defaultCharset());
    }

    /**
     * 获取指定编码字节数组。
     * @param str 文本
     * @param charset 编码
     * @return 字节数组
     */
    public static byte[] bytes(@Nullable CharSequence str, @Nullable String charset) {
        Charset actual = isBlank(charset) ? Charset.defaultCharset() : Charset.forName(charset);
        return bytes(str, actual);
    }

    /**
     * 获取指定编码字节数组。
     * @param str 文本
     * @param charset 编码
     * @return 字节数组
     */
    public static byte[] bytes(@Nullable CharSequence str, @Nullable Charset charset) {
        if (str == null) return null;
        return charset == null ? str.toString().getBytes() : str.toString().getBytes(charset);
    }

    /**
     * 转为 ByteBuffer。
     * @param str 文本
     * @param charset 编码
     * @return ByteBuffer
     */
    public static @NotNull ByteBuffer byteBuffer(@Nullable CharSequence str, @Nullable String charset) {
        return ByteBuffer.wrap(bytes(str, charset));
    }

    /**
     * 包裹字符串。
     * @param str 文本
     * @param prefixAndSuffix 前后缀
     * @return 结果文本
     */
    public static @NotNull String wrap(@Nullable CharSequence str, @Nullable CharSequence prefixAndSuffix) {
        return wrap(str, prefixAndSuffix, prefixAndSuffix);
    }

    /**
     * 包裹字符串。
     * @param str 文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @NotNull String wrap(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence suffix) {
        return nullToEmpty(prefix).concat(nullToEmpty(str)).concat(nullToEmpty(suffix));
    }

    /**
     * 批量包裹字符串。
     * @param prefixAndSuffix 前后缀
     * @param strs 文本列表
     * @return 结果数组
     */
    public static @NotNull String[] wrapAllWithPair(@Nullable CharSequence prefixAndSuffix, @Nullable CharSequence... strs) {
        return wrapAll(prefixAndSuffix, prefixAndSuffix, strs);
    }

    /**
     * 批量包裹字符串。
     * @param prefix 前缀
     * @param suffix 后缀
     * @param strs 文本列表
     * @return 结果数组
     */
    public static @NotNull String[] wrapAll(@Nullable CharSequence prefix, @Nullable CharSequence suffix, @Nullable CharSequence... strs) {
        if (strs == null) return new String[0];
        String[] results = new String[strs.length];
        for (int i = 0; i < strs.length; i++) {
            results[i] = wrap(strs[i], prefix, suffix);
        }
        return results;
    }

    /**
     * 如缺失则包裹。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @NotNull String wrapIfMissing(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence suffix) {
        int len = 0;
        if (isNotEmpty(str)) len += str.length();
        if (isNotEmpty(prefix)) len += prefix.length();
        if (isNotEmpty(suffix)) len += suffix.length();
        StringBuilder sb = new StringBuilder(len);
        if (isNotEmpty(prefix) && !startWith(str, prefix)) {
            sb.append(prefix);
        }
        if (isNotEmpty(str)) {
            sb.append(str);
        }
        if (isNotEmpty(suffix) && !endWith(str, suffix)) {
            sb.append(suffix);
        }
        return sb.toString();
    }

    /**
     * 批量包裹（缺失时才补）。
     * @param prefixAndSuffix 前后缀
     * @param strs 文本列表
     * @return 结果数组
     */
    public static @NotNull String[] wrapAllWithPairIfMissing(@Nullable CharSequence prefixAndSuffix, @Nullable CharSequence... strs) {
        return wrapAllIfMissing(prefixAndSuffix, prefixAndSuffix, strs);
    }

    /**
     * 批量包裹（缺失时才补）。
     * @param prefix 前缀
     * @param suffix 后缀
     * @param strs 文本列表
     * @return 结果数组
     */
    public static @NotNull String[] wrapAllIfMissing(@Nullable CharSequence prefix, @Nullable CharSequence suffix, @Nullable CharSequence... strs) {
        if (strs == null) return new String[0];
        String[] results = new String[strs.length];
        for (int i = 0; i < strs.length; i++) {
            results[i] = wrapIfMissing(strs[i], prefix, suffix);
        }
        return results;
    }

    /**
     * 去除包裹。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 结果文本
     */
    public static @Nullable String unWrap(@Nullable CharSequence str, @Nullable String prefix, @Nullable String suffix) {
        if (str == null) return null;
        return isWrap(str, prefix, suffix) ? sub(str, prefix.length(), str.length() - suffix.length()) : str.toString();
    }

    /**
     * 去除包裹。
     * @param str 原始文本
     * @param prefix 前缀字符
     * @param suffix 后缀字符
     * @return 结果文本
     */
    public static @Nullable String unWrap(@Nullable CharSequence str, char prefix, char suffix) {
        if (isEmpty(str)) return str(str);
        return str.charAt(0) == prefix && str.charAt(str.length() - 1) == suffix ? sub(str, 1, str.length() - 1) : str.toString();
    }

    /**
     * 去除包裹。
     * @param str 原始文本
     * @param prefixAndSuffix 前后缀字符
     * @return 结果文本
     */
    public static @Nullable String unWrap(@Nullable CharSequence str, char prefixAndSuffix) {
        return unWrap(str, prefixAndSuffix, prefixAndSuffix);
    }

    /**
     * 是否被包裹。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 是否包裹
     */
    public static boolean isWrap(@Nullable CharSequence str, @Nullable String prefix, @Nullable String suffix) {
        if (str == null || prefix == null || suffix == null) return false;
        String str2 = str.toString();
        return str2.startsWith(prefix) && str2.endsWith(suffix);
    }

    /**
     * 是否被包裹。
     * @param str 原始文本
     * @param wrapper 前后缀
     * @return 是否包裹
     */
    public static boolean isWrap(@Nullable CharSequence str, @Nullable String wrapper) {
        return isWrap(str, wrapper, wrapper);
    }

    /**
     * 是否被包裹。
     * @param str 原始文本
     * @param wrapper 前后缀字符
     * @return 是否包裹
     */
    public static boolean isWrap(@Nullable CharSequence str, char wrapper) {
        return isWrap(str, wrapper, wrapper);
    }

    /**
     * 是否被包裹。
     * @param str 原始文本
     * @param prefixChar 前缀字符
     * @param suffixChar 后缀字符
     * @return 是否包裹
     */
    public static boolean isWrap(@Nullable CharSequence str, char prefixChar, char suffixChar) {
        if (str == null || str.length() == 0) return false;
        return str.charAt(0) == prefixChar && str.charAt(str.length() - 1) == suffixChar;
    }

    /**
     * 左侧补齐。
     * @param str 原始文本
     * @param length 目标长度
     * @param padStr 填充字符串
     * @return 补齐结果
     */
    public static @Nullable String padPre(@Nullable CharSequence str, int length, @Nullable CharSequence padStr) {
        if (str == null) return null;
        int strLen = str.length();
        if (strLen == length) return str.toString();
        if (strLen > length) return subPre(str, length);
        return repeatByLength(padStr, length - strLen).concat(str.toString());
    }

    /**
     * 左侧补齐。
     * @param str 原始文本
     * @param length 目标长度
     * @param padChar 填充字符
     * @return 补齐结果
     */
    public static @Nullable String padPre(@Nullable CharSequence str, int length, char padChar) {
        if (str == null) return null;
        int strLen = str.length();
        if (strLen == length) return str.toString();
        if (strLen > length) return subPre(str, length);
        return repeat(padChar, length - strLen).concat(str.toString());
    }

    /**
     * 右侧补齐。
     * @param str 原始文本
     * @param length 目标长度
     * @param padChar 填充字符
     * @return 补齐结果
     */
    public static @Nullable String padAfter(@Nullable CharSequence str, int length, char padChar) {
        if (str == null) return null;
        int strLen = str.length();
        if (strLen == length) return str.toString();
        if (strLen > length) return sub(str, strLen - length, strLen);
        return str.toString().concat(repeat(padChar, length - strLen));
    }

    /**
     * 右侧补齐。
     * @param str 原始文本
     * @param length 目标长度
     * @param padStr 填充字符串
     * @return 补齐结果
     */
    public static @Nullable String padAfter(@Nullable CharSequence str, int length, @Nullable CharSequence padStr) {
        if (str == null) return null;
        int strLen = str.length();
        if (strLen == length) return str.toString();
        if (strLen > length) return subSufByLength(str, length);
        return str.toString().concat(repeatByLength(padStr, length - strLen));
    }

    /**
     * 居中补齐。
     * @param str 原始文本
     * @param size 总长度
     * @return 结果文本
     */
    public static @Nullable String center(@Nullable CharSequence str, int size) {
        return center(str, size, ' ');
    }

    /**
     * 居中补齐。
     * @param str 原始文本
     * @param size 总长度
     * @param padChar 填充字符
     * @return 结果文本
     */
    public static @Nullable String center(@Nullable CharSequence str, int size, char padChar) {
        if (str == null || size <= 0) return str(str);
        int strLen = str.length();
        int pads = size - strLen;
        if (pads <= 0) return str.toString();
        CharSequence result = padPre(str, strLen + pads / 2, padChar);
        return padAfter(result, size, padChar).toString();
    }

    /**
     * 居中补齐。
     * @param str 原始文本
     * @param size 总长度
     * @param padStr 填充字符串
     * @return 结果文本
     */
    public static @Nullable String center(@Nullable CharSequence str, int size, @Nullable CharSequence padStr) {
        if (str == null || size <= 0) return str(str);
        if (isEmpty(padStr)) {
            padStr = SPACE;
        }
        int strLen = str.length();
        int pads = size - strLen;
        if (pads <= 0) return str.toString();
        CharSequence result = padPre(str, strLen + pads / 2, padStr);
        return padAfter(result, size, padStr).toString();
    }

    /**
     * 转字符串（null 返回 null）。
     * @param cs 文本
     * @return 字符串
     */
    public static @Nullable String str(@Nullable CharSequence cs) {
        return cs == null ? null : cs.toString();
    }

    /**
     * 统计子串出现次数。
     * @param content 原始文本
     * @param strForSearch 目标子串
     * @return 次数
     */
    public static int count(@Nullable CharSequence content, @Nullable CharSequence strForSearch) {
        if (hasEmpty(content, strForSearch) || strForSearch.length() > content.length()) {
            return 0;
        }
        int count = 0;
        int idx = 0;
        String content2 = content.toString();
        String strForSearch2 = strForSearch.toString();
        while ((idx = content2.indexOf(strForSearch2, idx)) > -1) {
            count++;
            idx += strForSearch.length();
        }
        return count;
    }

    /**
     * 统计字符出现次数。
     * @param content 原始文本
     * @param charForSearch 目标字符
     * @return 次数
     */
    public static int count(@Nullable CharSequence content, char charForSearch) {
        if (isEmpty(content)) return 0;
        int count = 0;
        int contentLength = content.length();
        for (int i = 0; i < contentLength; i++) {
            if (charForSearch == content.charAt(i)) {
                count++;
            }
        }
        return count;
    }

    /**
     * 比较字符串。
     * @param str1 文本1
     * @param str2 文本2
     * @param nullIsLess null 是否更小
     * @return 比较结果
     */
    public static int compare(@Nullable CharSequence str1, @Nullable CharSequence str2, boolean nullIsLess) {
        if (str1 == str2) return 0;
        if (str1 == null) return nullIsLess ? -1 : 1;
        if (str2 == null) return nullIsLess ? 1 : -1;
        return str1.toString().compareTo(str2.toString());
    }

    /**
     * 比较字符串（忽略大小写）。
     * @param str1 文本1
     * @param str2 文本2
     * @param nullIsLess null 是否更小
     * @return 比较结果
     */
    public static int compareIgnoreCase(@Nullable CharSequence str1, @Nullable CharSequence str2, boolean nullIsLess) {
        if (str1 == str2) return 0;
        if (str1 == null) return nullIsLess ? -1 : 1;
        if (str2 == null) return nullIsLess ? 1 : -1;
        return str1.toString().compareToIgnoreCase(str2.toString());
    }

    /**
     * 比较版本号。
     * @param version1 版本1
     * @param version2 版本2
     * @return 比较结果
     */
    public static int compareVersion(@Nullable CharSequence version1, @Nullable CharSequence version2) {
        String v1 = str(version1);
        String v2 = str(version2);
        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;
        String[] p1 = v1.split("[.-]");
        String[] p2 = v2.split("[.-]");
        int len = Math.max(p1.length, p2.length);
        for (int i = 0; i < len; i++) {
            String a = i < p1.length ? p1[i] : "0";
            String b = i < p2.length ? p2[i] : "0";
            int cmp = compareVersionPart(a, b);
            if (cmp != 0) return cmp;
        }
        return 0;
    }

    private static int compareVersionPart(@NotNull String a, @NotNull String b) {
        boolean numA = isNumeric(a);
        boolean numB = isNumeric(b);
        if (numA && numB) {
            if (a.length() != b.length()) {
                return a.length() > b.length() ? 1 : -1;
            }
            return a.compareTo(b);
        }
        return a.compareToIgnoreCase(b);
    }

    /**
     * 如缺失则追加后缀。
     * @param str 原始文本
     * @param suffix 后缀
     * @param suffixes 额外后缀
     * @return 结果文本
     */
    public static @Nullable String appendIfMissing(@Nullable CharSequence str, @Nullable CharSequence suffix, @Nullable CharSequence... suffixes) {
        return appendIfMissing(str, suffix, false, suffixes);
    }

    /**
     * 如缺失则追加后缀（忽略大小写）。
     * @param str 原始文本
     * @param suffix 后缀
     * @param suffixes 额外后缀
     * @return 结果文本
     */
    public static @Nullable String appendIfMissingIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence suffix, @Nullable CharSequence... suffixes) {
        return appendIfMissing(str, suffix, true, suffixes);
    }

    /**
     * 如缺失则追加后缀。
     * @param str 原始文本
     * @param suffix 后缀
     * @param ignoreCase 是否忽略大小写
     * @param testSuffixes 额外后缀
     * @return 结果文本
     */
    public static @Nullable String appendIfMissing(@Nullable CharSequence str, @Nullable CharSequence suffix, boolean ignoreCase, @Nullable CharSequence... testSuffixes) {
        if (str != null && !isEmpty(suffix) && !endWith(str, suffix, ignoreCase)) {
            if (!isArrayEmpty(testSuffixes)) {
                for (CharSequence testSuffix : testSuffixes) {
                    if (endWith(str, testSuffix, ignoreCase)) {
                        return str.toString();
                    }
                }
            }
            return str.toString().concat(suffix.toString());
        }
        return str(str);
    }

    /**
     * 如缺失则追加前缀。
     * @param str 原始文本
     * @param prefix 前缀
     * @param prefixes 额外前缀
     * @return 结果文本
     */
    public static @Nullable String prependIfMissing(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence... prefixes) {
        return prependIfMissing(str, prefix, false, prefixes);
    }

    /**
     * 如缺失则追加前缀（忽略大小写）。
     * @param str 原始文本
     * @param prefix 前缀
     * @param prefixes 额外前缀
     * @return 结果文本
     */
    public static @Nullable String prependIfMissingIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence... prefixes) {
        return prependIfMissing(str, prefix, true, prefixes);
    }

    /**
     * 如缺失则追加前缀。
     * @param str 原始文本
     * @param prefix 前缀
     * @param ignoreCase 是否忽略大小写
     * @param prefixes 额外前缀
     * @return 结果文本
     */
    public static @Nullable String prependIfMissing(@Nullable CharSequence str, @Nullable CharSequence prefix, boolean ignoreCase, @Nullable CharSequence... prefixes) {
        if (str != null && !isEmpty(prefix) && !startWith(str, prefix, ignoreCase)) {
            if (!isArrayEmpty(prefixes)) {
                for (CharSequence s : prefixes) {
                    if (startWith(str, s, ignoreCase)) {
                        return str.toString();
                    }
                }
            }
            return prefix.toString().concat(str.toString());
        }
        return str(str);
    }

    /**
     * 替换子串（忽略大小写）。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacement 替换为
     * @return 结果文本
     */
    public static @Nullable String replaceIgnoreCase(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacement) {
        return replace(str, 0, searchStr, replacement, true);
    }

    /**
     * 替换子串。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacement 替换为
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacement) {
        return replace(str, 0, searchStr, replacement, false);
    }

    /**
     * 替换子串。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacement 替换为
     * @param ignoreCase 是否忽略大小写
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacement, boolean ignoreCase) {
        return replace(str, 0, searchStr, replacement, ignoreCase);
    }

    /**
     * 替换子串（从指定位置开始）。
     * @param str 原始文本
     * @param fromIndex 起始位置
     * @param searchStr 被替换子串
     * @param replacement 替换为
     * @param ignoreCase 是否忽略大小写
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, int fromIndex, @Nullable CharSequence searchStr, @Nullable CharSequence replacement, boolean ignoreCase) {
        if (isEmpty(str) || isEmpty(searchStr)) return str(str);
        if (replacement == null) replacement = EMPTY;
        int strLength = str.length();
        int searchStrLength = searchStr.length();
        if (strLength < searchStrLength || fromIndex > strLength) {
            return str(str);
        }
        if (fromIndex < 0) fromIndex = 0;
        StringBuilder result = new StringBuilder(strLength - searchStrLength + replacement.length());
        if (fromIndex != 0) {
            result.append(str.subSequence(0, fromIndex));
        }
        int preIndex;
        int index;
        for (preIndex = fromIndex; (index = indexOf(str, searchStr, preIndex, ignoreCase)) > -1; preIndex = index + searchStrLength) {
            result.append(str.subSequence(preIndex, index));
            result.append(replacement);
        }
        if (preIndex < strLength) {
            result.append(str.subSequence(preIndex, strLength));
        }
        return result.toString();
    }

    /**
     * 替换指定区间字符。
     * @param str 原始文本
     * @param startInclude 起始位置
     * @param endExclude 结束位置
     * @param replacedChar 替换字符
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, int startInclude, int endExclude, char replacedChar) {
        if (isEmpty(str)) return str(str);
        String originalStr = str(str);
        int[] strCodePoints = originalStr.codePoints().toArray();
        int strLength = strCodePoints.length;
        if (startInclude > strLength) return originalStr;
        if (endExclude > strLength) endExclude = strLength;
        if (startInclude > endExclude) return originalStr;
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < strLength; i++) {
            if (i >= startInclude && i < endExclude) {
                stringBuilder.append(replacedChar);
            } else {
                stringBuilder.append(new String(strCodePoints, i, 1));
            }
        }
        return stringBuilder.toString();
    }

    /**
     * 替换指定区间字符串。
     * @param str 原始文本
     * @param startInclude 起始位置
     * @param endExclude 结束位置
     * @param replacedStr 替换内容
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, int startInclude, int endExclude, @Nullable CharSequence replacedStr) {
        if (isEmpty(str)) return str(str);
        String originalStr = str(str);
        int[] strCodePoints = originalStr.codePoints().toArray();
        int strLength = strCodePoints.length;
        if (startInclude > strLength) return originalStr;
        if (endExclude > strLength) endExclude = strLength;
        if (startInclude > endExclude) return originalStr;
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < startInclude; i++) {
            stringBuilder.append(new String(strCodePoints, i, 1));
        }
        stringBuilder.append(replacedStr);
        for (int i = endExclude; i < strLength; i++) {
            stringBuilder.append(new String(strCodePoints, i, 1));
        }
        return stringBuilder.toString();
    }

    /**
     * 正则替换（函数式）。
     * @param str 原始文本
     * @param pattern 模式
     * @param replaceFun 替换函数
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, @Nullable Pattern pattern, @Nullable Function<Matcher, String> replaceFun) {
        if (str == null || pattern == null || replaceFun == null) return str(str);
        Matcher matcher = pattern.matcher(str);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String replacement = replaceFun.apply(matcher);
            matcher.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf(replacement)));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * 正则替换（函数式）。
     * @param str 原始文本
     * @param regex 正则
     * @param replaceFun 替换函数
     * @return 结果文本
     */
    public static @Nullable String replace(@Nullable CharSequence str, @Nullable String regex, @Nullable Function<Matcher, String> replaceFun) {
        if (regex == null) return str(str);
        return replace(str, Pattern.compile(regex), replaceFun);
    }

    /**
     * 替换最后一次匹配。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacedStr 替换内容
     * @return 结果文本
     */
    public static @Nullable String replaceLast(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacedStr) {
        return replaceLast(str, searchStr, replacedStr, false);
    }

    /**
     * 替换最后一次匹配。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacedStr 替换内容
     * @param ignoreCase 是否忽略大小写
     * @return 结果文本
     */
    public static @Nullable String replaceLast(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacedStr, boolean ignoreCase) {
        if (isEmpty(str)) return str(str);
        int lastIndex = lastIndexOf(str, searchStr, str.length(), ignoreCase);
        return lastIndex == -1 ? str(str) : replace(str, lastIndex, searchStr, replacedStr, ignoreCase);
    }

    /**
     * 替换首次匹配。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacedStr 替换内容
     * @return 结果文本
     */
    public static @Nullable String replaceFirst(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacedStr) {
        return replaceFirst(str, searchStr, replacedStr, false);
    }

    /**
     * 替换首次匹配。
     * @param str 原始文本
     * @param searchStr 被替换子串
     * @param replacedStr 替换内容
     * @param ignoreCase 是否忽略大小写
     * @return 结果文本
     */
    public static @Nullable String replaceFirst(@Nullable CharSequence str, @Nullable CharSequence searchStr, @Nullable CharSequence replacedStr, boolean ignoreCase) {
        if (isEmpty(str)) return str(str);
        int startInclude = indexOf(str, searchStr, 0, ignoreCase);
        return startInclude == -1 ? str(str) : replace(str, startInclude, startInclude + searchStr.length(), replacedStr);
    }

    /**
     * 隐藏指定区间字符。
     * @param str 原始文本
     * @param startInclude 起始位置
     * @param endExclude 结束位置
     * @return 结果文本
     */
    public static @Nullable String hide(@Nullable CharSequence str, int startInclude, int endExclude) {
        return replace(str, startInclude, endExclude, '*');
    }

    /**
     * 替换指定字符集合。
     * @param str 原始文本
     * @param chars 待替换字符
     * @param replacedStr 替换内容
     * @return 结果文本
     */
    public static @Nullable String replaceChars(@Nullable CharSequence str, @Nullable String chars, @Nullable CharSequence replacedStr) {
        return isEmpty(str) || isEmpty(chars) ? str(str) : replaceChars(str, chars.toCharArray(), replacedStr);
    }

    /**
     * 替换指定字符集合。
     * @param str 原始文本
     * @param chars 待替换字符
     * @param replacedStr 替换内容
     * @return 结果文本
     */
    public static @Nullable String replaceChars(@Nullable CharSequence str, @Nullable char[] chars, @Nullable CharSequence replacedStr) {
        if (isEmpty(str) || isCharArrayEmpty(chars)) return str(str);
        Set<Character> set = new HashSet<>(chars.length);
        for (char c : chars) {
            set.add(c);
        }
        StringBuilder builder = new StringBuilder();
        String replaced = String.valueOf(replacedStr);
        int strLen = str.length();
        for (int i = 0; i < strLen; i++) {
            char c = str.charAt(i);
            builder.append(set.contains(c) ? replaced : c);
        }
        return builder.toString();
    }

    /**
     * 获取长度（null 返回 0）。
     * @param cs 文本
     * @return 长度
     */
    public static int length(@Nullable CharSequence cs) {
        return cs == null ? 0 : cs.length();
    }

    /**
     * 获取字节长度。
     * @param cs 文本
     * @param charset 编码
     * @return 字节长度
     */
    public static int byteLength(@Nullable CharSequence cs, @NotNull Charset charset) {
        return cs == null ? 0 : cs.toString().getBytes(charset).length;
    }

    /**
     * 统计总长度。
     * @param strs 文本列表
     * @return 总长度
     */
    public static int totalLength(@Nullable CharSequence... strs) {
        int totalLength = 0;
        if (strs == null) return 0;
        for (CharSequence str : strs) {
            totalLength += str == null ? 0 : str.length();
        }
        return totalLength;
    }

    /**
     * 限制最大长度。
     * @param string 原始文本
     * @param length 最大长度
     * @return 结果文本
     */
    public static @Nullable String maxLength(@Nullable CharSequence string, int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be > 0");
        }
        if (string == null) return null;
        return string.length() <= length ? string.toString() : String.format("%s...", sub(string, 0, length));
    }

    /**
     * 获取首个非 null。
     * @param strs 文本列表
     * @param <T> 类型
     * @return 首个非 null
     */
    @SafeVarargs
    public static <T extends CharSequence> @Nullable T firstNonNull(@Nullable T... strs) {
        if (strs == null) return null;
        for (T str : strs) {
            if (str != null) return str;
        }
        return null;
    }

    /**
     * 获取首个非空字符串。
     * @param strs 文本列表
     * @param <T> 类型
     * @return 首个非空
     */
    @SafeVarargs
    public static <T extends CharSequence> @Nullable T firstNonEmpty(@Nullable T... strs) {
        if (strs == null) return null;
        for (T str : strs) {
            if (isNotEmpty(str)) return str;
        }
        return null;
    }

    /**
     * 获取首个非空白字符串。
     * @param strs 文本列表
     * @param <T> 类型
     * @return 首个非空白
     */
    @SafeVarargs
    public static <T extends CharSequence> @Nullable T firstNonBlank(@Nullable T... strs) {
        if (strs == null) return null;
        for (T str : strs) {
            if (isNotBlank(str)) return str;
        }
        return null;
    }

    /**
     * 首字母大写并加前缀。
     * @param str 原始文本
     * @param preString 前缀
     * @return 结果文本
     */
    public static @Nullable String upperFirstAndAddPre(@Nullable CharSequence str, @Nullable String preString) {
        return str != null && preString != null ? String.format("%s%s", preString, upperFirst(str)) : null;
    }

    /**
     * 首字母大写。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String upperFirst(@Nullable CharSequence str) {
        if (str == null) return null;
        if (str.length() > 0) {
            char firstChar = str.charAt(0);
            if (Character.isLowerCase(firstChar)) {
                return String.format("%c%s", Character.toUpperCase(firstChar), subSuf(str, 1));
            }
        }
        return str.toString();
    }

    /**
     * 首字母小写。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String lowerFirst(@Nullable CharSequence str) {
        if (str == null) return null;
        if (str.length() > 0) {
            char firstChar = str.charAt(0);
            if (Character.isUpperCase(firstChar)) {
                return String.format("%c%s", Character.toLowerCase(firstChar), subSuf(str, 1));
            }
        }
        return str.toString();
    }

    /**
     * 过滤字符。
     * @param str 原始文本
     * @param filter 过滤器
     * @return 结果文本
     */
    public static @Nullable String filter(@Nullable CharSequence str, @Nullable Predicate<Character> filter) {
        if (str == null || filter == null) return str(str);
        int len = str.length();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = str.charAt(i);
            if (filter.test(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * 是否全为大写（不含小写即视为 true）。
     * @param str 原始文本
     * @return 是否全大写
     */
    public static boolean isUpperCase(@Nullable CharSequence str) {
        if (str == null) return false;
        int len = str.length();
        for (int i = 0; i < len; i++) {
            if (Character.isLowerCase(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 是否全为小写（不含大写即视为 true）。
     * @param str 原始文本
     * @return 是否全小写
     */
    public static boolean isLowerCase(@Nullable CharSequence str) {
        if (str == null) return false;
        int len = str.length();
        for (int i = 0; i < len; i++) {
            if (Character.isUpperCase(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 大小写互换。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String swapCase(@Nullable String str) {
        if (isEmpty(str)) return str;
        char[] buffer = str.toCharArray();
        for (int i = 0; i < buffer.length; i++) {
            char ch = buffer[i];
            if (Character.isUpperCase(ch) || Character.isTitleCase(ch)) {
                buffer[i] = Character.toLowerCase(ch);
            } else if (Character.isLowerCase(ch)) {
                buffer[i] = Character.toUpperCase(ch);
            }
        }
        return new String(buffer);
    }

    /**
     * 转为下划线格式。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String toUnderlineCase(@Nullable CharSequence str) {
        return toSymbolCase(str, '_');
    }

    /**
     * 转为指定符号格式。
     * @param str 原始文本
     * @param symbol 分隔符
     * @return 结果文本
     */
    public static @Nullable String toSymbolCase(@Nullable CharSequence str, char symbol) {
        if (str == null) return null;
        String text = str.toString();
        StringBuilder sb = new StringBuilder(text.length() + 8);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (isSeparator(c, symbol)) {
                if (sb.length() > 0 && sb.charAt(sb.length() - 1) != symbol) {
                    sb.append(symbol);
                }
                continue;
            }
            if (Character.isUpperCase(c)) {
                if (sb.length() > 0) {
                    char prev = text.charAt(i - 1);
                    if (!isSeparator(prev, symbol) && (Character.isLowerCase(prev) || Character.isDigit(prev))) {
                        sb.append(symbol);
                    }
                }
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * 转为驼峰格式（默认 '_' 分隔）。
     * @param name 原始文本
     * @return 结果文本
     */
    public static @Nullable String toCamelCase(@Nullable CharSequence name) {
        return toCamelCase(name, '_');
    }

    /**
     * 转为驼峰格式。
     * @param name 原始文本
     * @param symbol 分隔符
     * @return 结果文本
     */
    public static @Nullable String toCamelCase(@Nullable CharSequence name, char symbol) {
        if (name == null) return null;
        String text = name.toString();
        StringBuilder sb = new StringBuilder(text.length());
        boolean upperNext = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (isSeparator(c, symbol)) {
                upperNext = true;
                continue;
            }
            if (sb.length() == 0) {
                sb.append(Character.toLowerCase(c));
                upperNext = false;
                continue;
            }
            if (upperNext) {
                sb.append(Character.toUpperCase(c));
                upperNext = false;
            } else {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }

    /**
     * 判断是否被指定前后缀包围。
     * @param str 原始文本
     * @param prefix 前缀
     * @param suffix 后缀
     * @return 是否包围
     */
    public static boolean isSurround(@Nullable CharSequence str, @Nullable CharSequence prefix, @Nullable CharSequence suffix) {
        if (isBlank(str) || prefix == null || suffix == null) return false;
        if (str.length() < prefix.length() + suffix.length()) return false;
        String str2 = str.toString();
        return str2.startsWith(prefix.toString()) && str2.endsWith(suffix.toString());
    }

    /**
     * 判断是否被指定前后缀包围。
     * @param str 原始文本
     * @param prefix 前缀字符
     * @param suffix 后缀字符
     * @return 是否包围
     */
    public static boolean isSurround(@Nullable CharSequence str, char prefix, char suffix) {
        if (isBlank(str)) return false;
        if (str.length() < 2) return false;
        return str.charAt(0) == prefix && str.charAt(str.length() - 1) == suffix;
    }

    /**
     * 构建 StringBuilder。
     * @param strs 文本列表
     * @return StringBuilder
     */
    public static @NotNull StringBuilder builder(@Nullable CharSequence... strs) {
        StringBuilder sb = new StringBuilder();
        if (strs != null) {
            for (CharSequence str : strs) {
                sb.append(str);
            }
        }
        return sb;
    }

    /**
     * 根据 getter/setter 获取字段名。
     * @param getOrSetMethodName 方法名
     * @return 字段名
     */
    public static @Nullable String getGeneralField(@Nullable CharSequence getOrSetMethodName) {
        if (getOrSetMethodName == null) return null;
        String name = getOrSetMethodName.toString();
        if (!name.startsWith("get") && !name.startsWith("set")) {
            return name.startsWith("is") ? removePreAndLowerFirst(getOrSetMethodName, 2) : name;
        }
        return removePreAndLowerFirst(getOrSetMethodName, 3);
    }

    /**
     * 生成 setter 名称。
     * @param fieldName 字段名
     * @return setter 名称
     */
    public static @Nullable String genSetter(@Nullable CharSequence fieldName) {
        return upperFirstAndAddPre(fieldName, "set");
    }

    /**
     * 生成 getter 名称。
     * @param fieldName 字段名
     * @return getter 名称
     */
    public static @Nullable String genGetter(@Nullable CharSequence fieldName) {
        return upperFirstAndAddPre(fieldName, "get");
    }

    /**
     * 拼接字符串。
     * @param isNullToEmpty 是否将 null 视为 ""
     * @param strs 文本列表
     * @return 结果文本
     */
    public static @NotNull String concat(boolean isNullToEmpty, @Nullable CharSequence... strs) {
        StringBuilder sb = new StringBuilder();
        if (strs != null) {
            for (CharSequence str : strs) {
                sb.append(isNullToEmpty ? nullToEmpty(str) : str);
            }
        }
        return sb.toString();
    }

    /**
     * 生成简短字符串。
     * @param str 原始文本
     * @param maxLength 最大长度
     * @return 简短结果
     */
    public static @Nullable String brief(@Nullable CharSequence str, int maxLength) {
        if (str == null) return null;
        int strLength = str.length();
        if (maxLength > 0 && strLength > maxLength) {
            switch (maxLength) {
                case 1:
                    return String.valueOf(str.charAt(0));
                case 2:
                    return String.format("%c.", str.charAt(0));
                case 3:
                    return String.format("%c.%c", str.charAt(0), str.charAt(strLength - 1));
                case 4:
                    return String.format("%c..%c", str.charAt(0), str.charAt(strLength - 1));
                default:
                    int suffixLength = (maxLength - 3) / 2;
                    int preLength = suffixLength + (maxLength - 3) % 2;
                    String str2 = str.toString();
                    return format("{}...{}", str2.substring(0, preLength), str2.substring(strLength - suffixLength));
            }
        }
        return str.toString();
    }

    /**
     * 连接对象数组。
     * @param conjunction 分隔符
     * @param objs 对象列表
     * @return 结果文本
     */
    public static @NotNull String join(@Nullable CharSequence conjunction, @Nullable Object... objs) {
        if (objs == null || objs.length == 0) return EMPTY;
        String sep = conjunction == null ? EMPTY : conjunction.toString();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < objs.length; i++) {
            if (i > 0) sb.append(sep);
            sb.append(objs[i]);
        }
        return sb.toString();
    }

    /**
     * 连接迭代器。
     * @param conjunction 分隔符
     * @param iterable 迭代器
     * @param <T> 类型
     * @return 结果文本
     */
    public static <T> @NotNull String join(@Nullable CharSequence conjunction, @Nullable Iterable<T> iterable) {
        if (iterable == null) return EMPTY;
        String sep = conjunction == null ? EMPTY : conjunction.toString();
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (T item : iterable) {
            if (!first) sb.append(sep);
            sb.append(item);
            first = false;
        }
        return sb.toString();
    }

    /**
     * 是否全部字符满足匹配规则。
     * @param value 原始文本
     * @param matcher 匹配函数
     * @return 是否全部匹配
     */
    public static boolean isAllCharMatch(@Nullable CharSequence value, @Nullable Predicate<Character> matcher) {
        if (isBlank(value) || matcher == null) return false;
        int i = value.length();
        while (--i >= 0) {
            if (!matcher.test(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 是否为数字字符串。
     * @param str 原始文本
     * @return 是否为数字
     */
    public static boolean isNumeric(@Nullable CharSequence str) {
        return isAllCharMatch(str, Character::isDigit);
    }

    /**
     * 移动子串位置。
     * @param str 原始文本
     * @param startInclude 起始位置
     * @param endExclude 结束位置
     * @param moveLength 移动长度
     * @return 结果文本
     */
    public static @Nullable String move(@Nullable CharSequence str, int startInclude, int endExclude, int moveLength) {
        if (isEmpty(str)) return str(str);
        int len = str.length();
        if (Math.abs(moveLength) > len) {
            moveLength %= len;
        }
        StringBuilder strBuilder = new StringBuilder(len);
        if (moveLength > 0) {
            int endAfterMove = Math.min(endExclude + moveLength, str.length());
            strBuilder.append(str.subSequence(0, startInclude))
                    .append(str.subSequence(endExclude, endAfterMove))
                    .append(str.subSequence(startInclude, endExclude))
                    .append(str.subSequence(endAfterMove, str.length()));
        } else {
            if (moveLength >= 0) {
                return str(str);
            }
            int startAfterMove = Math.max(startInclude + moveLength, 0);
            strBuilder.append(str.subSequence(0, startAfterMove))
                    .append(str.subSequence(startInclude, endExclude))
                    .append(str.subSequence(startAfterMove, startInclude))
                    .append(str.subSequence(endExclude, str.length()));
        }
        return strBuilder.toString();
    }

    /**
     * 是否全部字符相同。
     * @param str 原始文本
     * @return 是否全部相同
     */
    public static boolean isCharEquals(@Nullable CharSequence str) {
        if (isEmpty(str)) {
            throw new IllegalArgumentException("Str to check must be not empty!");
        }
        return count(str, str.charAt(0)) == str.length();
    }

    /**
     * 规范化 Unicode 字符串（NFC）。
     * @param str 原始文本
     * @return 结果文本
     */
    public static @Nullable String normalize(@Nullable CharSequence str) {
        return str == null ? null : Normalizer.normalize(str, Form.NFC);
    }

    /**
     * 固定长度补齐（右侧）。
     * @param str 原始文本
     * @param fixedChar 填充字符
     * @param length 目标长度
     * @return 结果文本
     */
    public static @Nullable String fixLength(@Nullable CharSequence str, char fixedChar, int length) {
        if (str == null) return null;
        int fixedLength = length - str.length();
        return fixedLength <= 0 ? str.toString() : String.format("%s%s", str, repeat(fixedChar, fixedLength));
    }

    /**
     * 是否包含字母。
     * @param str 原始文本
     * @return 是否包含字母
     */
    public static boolean hasLetter(@Nullable CharSequence str) {
        if (str == null) return false;
        for (int i = 0; i < str.length(); i++) {
            if (Character.isLetter(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取公共前缀。
     * @param str1 文本1
     * @param str2 文本2
     * @return 公共前缀
     */
    public static @NotNull CharSequence commonPrefix(@Nullable CharSequence str1, @Nullable CharSequence str2) {
        if (isEmpty(str1) || isEmpty(str2)) return EMPTY;
        int minLength = Math.min(str1.length(), str2.length());
        int index = 0;
        while (index < minLength && str1.charAt(index) == str2.charAt(index)) {
            index++;
        }
        return str1.subSequence(0, index);
    }

    /**
     * 获取公共后缀。
     * @param str1 文本1
     * @param str2 文本2
     * @return 公共后缀
     */
    public static @NotNull CharSequence commonSuffix(@Nullable CharSequence str1, @Nullable CharSequence str2) {
        if (isEmpty(str1) || isEmpty(str2)) return EMPTY;
        int str1Index = str1.length() - 1;
        int str2Index = str2.length() - 1;
        while (str1Index >= 0 && str2Index >= 0 && str1.charAt(str1Index) == str2.charAt(str2Index)) {
            str1Index--;
            str2Index--;
        }
        return str1.subSequence(str1Index + 1, str1.length());
    }

    private static void addSplitPart(@NotNull List<String> result, @NotNull String part, boolean isTrim, boolean ignoreEmpty) {
        String value = isTrim ? trim(part) : part;
        if (!ignoreEmpty || value.length() > 0) {
            result.add(value);
        }
    }
}
