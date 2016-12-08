package com.softinite.spam.cli;

import java.io.Console;
import java.util.Set;

/**
 * Responsible for interacting with the user
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class UserInteraction {

    private static final Console CONSOLE = System.console();

    public String readRootPassoword() {
        showToUser("Please input root password:");
        return readSecret();
    }

    protected String readSecret() {
        return new String(CONSOLE.readPassword());
    }

    public void showToUser(String text) {
        System.out.println(text);
    }

    public void showSetToUser(Set<String> contentSet) {
        if (contentSet != null) {
            contentSet.stream().forEach(System.out::println);
        }
    }

    public String readAccountName() {
        showToUser("Please enter account name:");
        return CONSOLE.readLine();
    }

    public String readAccountSecret() {
        showToUser("Please enter account secret:");
        return readSecret();
    }
}
