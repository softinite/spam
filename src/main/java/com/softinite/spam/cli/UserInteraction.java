package com.softinite.spam.cli;

import org.apache.commons.lang3.StringUtils;

import java.io.Console;
import java.util.Set;

/**
 * Responsible for interacting with the user
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class UserInteraction {

    public static final String BLANK_NAME_NOT_ALLOWED = "Blank account name is not allowed!";
    private static final Console CONSOLE = System.console();

    public String readSPAMPassoword() {
        return readSPAMPassoword("Please input SPAM password:");
    }

    public String readSPAMPassoword(String msg) {
        showToUser(msg);
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
            contentSet.stream().sorted(String::compareToIgnoreCase).forEach(System.out::println);
        }
    }

    public String readAccountName() {
        showToUser("Please enter account name:");
        String accct = readLine();
        if (StringUtils.isBlank(accct)) {
            throw new RuntimeException(BLANK_NAME_NOT_ALLOWED);
        }
        return accct;
    }

    protected String readLine() {
        return CONSOLE.readLine();
    }

    public String readAccountSecret() {
        showToUser("Please enter account secret:");
        return readSecret();
    }

    public Boolean readYesNoAnswer() {
        String answer = readLine();
        return StringUtils.equalsAnyIgnoreCase("yes", answer);
    }

    public String readPasswordConfirmation() {
        showToUser("Please confirm password:");
        return readSecret();
    }

    public void showErrorToUser(String errorMsg) {
        System.err.println(errorMsg);
    }

    public String readSearchPattern() {
        showToUser("Please enter the search pattern for the account:");
        return readLine();
    }
}
