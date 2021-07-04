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

    @Parameter(names = {"-dump", "-export"}, description = "Use this property to write all the information about all the accounts to given plaintext file.")
    private String dump;

    @Parameter(names = {"-import", "-intake"}, description = "Use this property to import accounts from a plaintext file in 'properties' format.")
    private String importFile;

    @Parameter(names = {"-merge"}, description = "Use this property to specify a file from which to merge accounts.")
    private String mergeFile;

}
