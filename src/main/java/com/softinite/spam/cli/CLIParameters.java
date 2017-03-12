package com.softinite.spam.cli;

import com.beust.jcommander.Parameter;
import lombok.Data;

/**
 * Responsible for mapping user arguments to Password manager's specific options.
 * Created by Sergiu Ivasenco on 1/14/17.
 */
@Data
public class CLIParameters {

    @Parameter(names = {"-help", "-h", "-?"}, description = "Displays all the available options.", help = true)
    private Boolean help = Boolean.FALSE;

    @Parameter(names = {"-file", "-f"}, description = "Use this property to specify the location of the encrypted file with passwords.")
    private String file;

    @Parameter(names = {"-create", "-c"}, description = "Use this option to create the password file.")
    private Boolean create = Boolean.FALSE;

    @Parameter(names = {"-list", "-l", "-names"}, description = "Specify this option to see the full list of available accounts.")
    private Boolean list = Boolean.FALSE;

    @Parameter(names = {"-new", "-n"}, description = "Use this option to add new account to be managed.")
    private Boolean newAcct = Boolean.FALSE;

    @Parameter(names = {"-show", "-display", "-s", "-d"}, description = "Use this option to see the secret for a specific account.")
    private Boolean show = Boolean.FALSE;

    @Parameter(names = {"-update", "-modify", "-u", "-m"}, description = "Use this option to update the secret for a specific account.")
    private Boolean update = Boolean.FALSE;

    @Parameter(names = {"-del", "-delete", "-remove"}, description = "Use this option to delete an account. Please use with caution.")
    private Boolean delete = Boolean.FALSE;

    @Parameter(names = {"-dump", "-export"}, description = "Use this property to write all the information about all the accounts to given plaintext file.")
    private String dump;

    @Parameter(names = {"-import", "-intake"}, description = "Use this property to import accounts from a plaintext file in 'properties' format.")
    private String importFile;

    @Parameter(names = {"-rename", "-r"}, description = "Use this option to rename an account.")
    private Boolean rename = Boolean.FALSE;

    @Parameter(names = {"-search", "-find", "-filter"}, description = "Use this option to search for accounts matching a certain pattern.")
    private Boolean search = Boolean.FALSE;

    @Parameter(names = {"-merge"}, description = "Use this property to specify a file from which to merge accounts.")
    private String mergeFile;
}
