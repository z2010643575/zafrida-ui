package com.zafrida.ui.templates;

import org.jetbrains.annotations.NotNull;

public final class ZaFridaTemplate {

    private final @NotNull String id;
    private final @NotNull String title;
    private final @NotNull String description;
    private final @NotNull ZaFridaTemplateCategory category;
    private final @NotNull String content;

    public ZaFridaTemplate(@NotNull String id,
                           @NotNull String title,
                           @NotNull String description,
                           @NotNull ZaFridaTemplateCategory category,
                           @NotNull String content) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.category = category;
        this.content = content;
    }

    public @NotNull String getId() {
        return id;
    }

    public @NotNull String getTitle() {
        return title;
    }

    public @NotNull String getDescription() {
        return description;
    }

    public @NotNull ZaFridaTemplateCategory getCategory() {
        return category;
    }

    public @NotNull String getContent() {
        return content;
    }
}
