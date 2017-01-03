package com.softinite.spam.cli;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * Responsible for holding command line options.
 * Created by Sergiu Ivasenco on 01/12/16.
 */
public enum SpamCLIOptions {
    HELP("help", Boolean.FALSE, "Displays all the available options."),
    FILE("file", Boolean.TRUE, "Use this property to specify the location of the encrypted file with passwords."),
    LIST_ACCTS_NAMES("list", Boolean.FALSE, "Specify this option to see the full list of available accounts."),
    CREATE("c", Boolean.FALSE, "Use this option to create the password file."),
    NEW_ACCT("new", Boolean.FALSE, "Use this option to add new account to be managed."),
    SHOW("show", Boolean.FALSE, "Use this option to see the secret for a specific account."),
    UPDATE("update", Boolean.FALSE, "Use this option to update the secret for a specific account."),
    DELETE("del", Boolean.FALSE, "Use this option to delete an account. Please use with caution."),
    DUMP("dump", Boolean.TRUE, "Use this property to write all the information about all the accounts to given plaintext file."),
    IMPORT("import", Boolean.TRUE, "Use this property to import accounts from a plaintext file in 'properties' format."),
    RENAME("rename", Boolean.FALSE, "Use this option to rename an account."),
    SEARCH("search", Boolean.FALSE, "Use this option to search for accounts matching a certain pattern.");

    private Option option;

    SpamCLIOptions(String name, Boolean requiresArgument, String description) {
        setOption(new Option(name, requiresArgument, description));
    }

    public static Options loadAllOptions() {
        Options options = new Options();
        for (SpamCLIOptions opt : values()) {
            options.addOption(opt.getOption());
        }
        return options;
    }

    public Option getOption() {
        return option;
    }

    private void setOption(Option option) {
        this.option = option;
    }

    public String getName() {
        return getOption().getOpt();
    }
}
