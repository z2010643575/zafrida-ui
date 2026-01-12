package com.zafrida.ui.templates;

public final class ZaFridaScriptSkeleton {

    private ZaFridaScriptSkeleton() {
    }

    public static final String TEXT = """
            'use strict';

            // ZAFrida Script Skeleton
            // Tips:
            // 1) Templates are managed by ZAFrida UI (checkbox -> insert/disable by comments)
            // 2) Do NOT delete markers unless you want to stop template management.

            function zlog(msg) {
              console.log("[ZAFrida] " + msg);
            }

            zlog("agent loaded");

            //== ZAFrida:TEMPLATES:BEGIN ==
            //== ZAFrida:TEMPLATES:END ==

            """;
}
