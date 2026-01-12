package com.zafrida.ui.ui.render;

import com.intellij.ui.ColoredListCellRenderer;
import com.intellij.ui.SimpleTextAttributes;
import com.zafrida.ui.frida.FridaProcess;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JList;

public final class ProcessCellRenderer extends ColoredListCellRenderer<FridaProcess> {
    @Override
    protected void customizeCellRenderer(@NotNull JList<? extends FridaProcess> list,
                                         @Nullable FridaProcess value,
                                         int index,
                                         boolean selected,
                                         boolean hasFocus) {
        if (value == null) {
            append("(null)", SimpleTextAttributes.ERROR_ATTRIBUTES);
            return;
        }

        String pidText = value.getPid() != null ? String.valueOf(value.getPid()) : "-";
        append(pidText, SimpleTextAttributes.REGULAR_BOLD_ATTRIBUTES);
        append("  ");
        append(value.getName(), SimpleTextAttributes.REGULAR_ATTRIBUTES);

        if (value.getIdentifier() != null && !value.getIdentifier().isBlank()) {
            append("  ");
            append(value.getIdentifier(), SimpleTextAttributes.GRAYED_ATTRIBUTES);
        }
    }
}
