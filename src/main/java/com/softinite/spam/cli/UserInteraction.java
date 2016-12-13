package com.softinite.spam.cli;

import org.apache.commons.lang3.StringUtils;

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
        String secret = new String(CONSOLE.readPassword());
        if (StringUtils.isBlank(secret)) {
            throw new RuntimeException("Blank value not allowed.");
        }
        return secret;
    }

    public void showToUser(String text) {
        System.out.println(text);
    }

    public void showSetToUser(Set<String> contentSet) {
        if (contentSet != null) {
            contentSet.forEach(System.out::println);
        }
    }

    public String readAccountName() {
        showToUser("Please enter account name:");
        String accct = CONSOLE.readLine();
        if (StringUtils.isBlank(accct)) {
            throw new RuntimeException("Blank account name is not allowed!");
        }
        return accct;
    }

    public String readAccountSecret() {
        showToUser("Please enter account secret:");
        return readSecret();
    }

    public Boolean readYesNoAnswer() {
        String answer = CONSOLE.readLine();
        return StringUtils.equalsAnyIgnoreCase("yes", answer);
    }

    public String readPasswordConfirmation() {
        showToUser("Please confirm password:");
        return readSecret();
    }

    public void showErrorToUser(String errorMsg) {
        System.err.println(errorMsg);
    }
}
