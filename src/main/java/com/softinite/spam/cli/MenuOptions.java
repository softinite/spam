package com.softinite.spam.cli;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

public enum MenuOptions {
    NONE(0, ""),
    LIST_SECRETS(1, "List all available secrets"),
    ADD_SECRET(2, "Add secret"),
    SHOW_SECRET(3, "Show secret"),
    UPDATE_SECRET(4, "Update secret"),
    REMOVE_SECRET(5, "Remove secret"),
    RENAME_SECRET(6, "Rename secret"),
    SEARCH_SECRET(7, "Search secrets"),
    QUIT(8, "Quit");

    @Getter
    @Setter(AccessLevel.PRIVATE)
    private Integer id;
    @Getter
    @Setter(AccessLevel.PRIVATE)
    private String label;

    MenuOptions(Integer id, String label) {
        setId(id);
        setLabel(label);
    }

    public static MenuOptions from(Integer id) {
        for(MenuOptions mo : values()) {
            if (mo.getId().equals(id)) {
                return mo;
            }
        }
        return MenuOptions.NONE;
    }
}
