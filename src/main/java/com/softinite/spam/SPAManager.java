package com.softinite.spam;

import com.softinite.spam.cli.SpamCLIOptions;
import com.softinite.spam.cli.UserInteraction;
import com.softinite.spam.encrdecr.FileProxy;
import com.softinite.spam.encrdecr.PasswordContainer;
import org.apache.commons.cli.*;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Logger;

/**
 * Responsible for starting the application
 * Created by Sergiu Ivasenco on 01/12/16.
 */
public class SPAManager {

    private static final Logger LOGGER = Logger.getLogger(SPAManager.class.getName());
    public static final String CMD_LINE_SYNTAX = "java -jar SPAM-1.0-SNAPSHOT-fat.jar <OPTIONS>";
    protected static final String ACCT_NOT_FOUND_MSG = "Could not locate account ";

    private Options availableOptions;
    private UserInteraction userInteraction;
    private PasswordContainer passwordContainer;

    public static void main(String[] args) throws ParseException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        LOGGER.info("Password manager has been started.");
        SPAManager manager = new SPAManager();
        manager.setAvailableOptions(SpamCLIOptions.loadAllOptions());
        manager.setPasswordContainer(new PasswordContainer());
        manager.setUserInteraction(new UserInteraction());
        CommandLineParser parser = new DefaultParser();
        LOGGER.info("Parsing command line options.");
        CommandLine commandLine = parser.parse(manager.getAvailableOptions(), args);

        LOGGER.info("Executing selected command.");
        manager.execute(commandLine);
    }

    public void showHelp() {
        LOGGER.info("Displaying help options to user.");
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp(CMD_LINE_SYNTAX, getAvailableOptions());
    }

    public Options getAvailableOptions() {
        return availableOptions;
    }

    public void setAvailableOptions(Options availableOptions) {
        this.availableOptions = availableOptions;
    }

    public void execute(CommandLine cmd) throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        String fileArgName = SpamCLIOptions.FILE.getName();
        LOGGER.info("Processing argument " + fileArgName);
        if (cmd.hasOption(fileArgName)) {
            LOGGER.info("File option found.");
            executeWithFileName(cmd.getOptionValue(fileArgName), cmd);
        } else {
            LOGGER.info("File option not found.");
            showHelp();
        }
    }

    public void executeWithFileName(String fileName, CommandLine cmd) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        LOGGER.info("Loading password file object " + fileName);
        FileProxy file = loadPasswordFileObject(fileName);
        executeWithFile(cmd, file);
    }

    protected void executeWithFile(CommandLine cmd, FileProxy file) throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
        if (file.exists()) {
            LOGGER.info("File exists.");
            String rootPassoword = getUserInteraction().readRootPassoword();
            getPasswordContainer().init(rootPassoword, file);
            executeUserCommand(cmd);
        } else if (cmd.hasOption(SpamCLIOptions.CREATE.getName())) {
            LOGGER.info("Creating the file.");
            createFile(file);
        } else {
            getUserInteraction().showToUser("Could not locate file " + file.getName());
        }
    }

    protected FileProxy loadPasswordFileObject(String fileName) {
        FileProxy fileProxy = new FileProxy();
        fileProxy.setInternal(new File(fileName));
        return fileProxy;
    }

    protected void executeUserCommand(CommandLine cmd) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (cmd.hasOption(SpamCLIOptions.LIST_ACCTS_NAMES.getName())) {
            listAllAccounts();
        } else if (cmd.hasOption(SpamCLIOptions.NEW_ACCT.getName())) {
            addAccount();
        } else if (cmd.hasOption(SpamCLIOptions.SHOW.getName())) {
            showSecret();
        } else if (cmd.hasOption(SpamCLIOptions.UPDATE.getName())) {
            modifySecret();
        } else if (cmd.hasOption(SpamCLIOptions.DELETE.getName())) {
            removeAccount();
        }
    }

    protected void createFile(FileProxy targetFile) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {
        String rootPassword = getUserInteraction().readRootPassoword();
        String confirmation = getUserInteraction().readPasswordConfirmation();
        if (StringUtils.equals(rootPassword, confirmation)) {
            targetFile.touch();
            getPasswordContainer().init(rootPassword, targetFile);
            getPasswordContainer().save();
        } else {
            throw new RuntimeException("Could not confirm passowrd difference= " + StringUtils.difference(rootPassword, confirmation));
        }
    }

    protected void listAllAccounts() {
        LOGGER.info("Listing all the accounts.");
        getUserInteraction().showSetToUser(getPasswordContainer().loadKeys());
    }

    protected void addAccount() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        LOGGER.info("Adding new account to manager's database.");
        String accountName = getUserInteraction().readAccountName();
        addAccount(accountName);
    }

    protected void addAccount(String accountName) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        LOGGER.info("Reading secret for account=" + accountName);
        String accountSecret = getUserInteraction().readAccountSecret();
        getPasswordContainer().addAccount(accountName, accountSecret);
        getPasswordContainer().save();
    }

    protected void showSecret() {
        LOGGER.info("Preparing to show the secret for an account.");
        String accountName = getUserInteraction().readAccountName();
        String secret = getPasswordContainer().loadSecret(accountName);
        if (secret == null) {
            getUserInteraction().showErrorToUser(ACCT_NOT_FOUND_MSG + accountName);
        } else {
            getUserInteraction().showToUser(secret);
        }
    }

    protected void modifySecret() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        LOGGER.info("Preparing to modify an account.");
        String accountName = getUserInteraction().readAccountName();
        if (getPasswordContainer().doesAccountExist(accountName)) {
            String accountSecret = getUserInteraction().readAccountSecret();
            getPasswordContainer().modify(accountName, accountSecret);
            getPasswordContainer().save();
        } else {
            getUserInteraction().showToUser("Could not find account with name " + accountName + ". Would you like to add it yes/no ? [no]");
            Boolean yes = getUserInteraction().readYesNoAnswer();
            if (yes) {
                addAccount(accountName);
            }
        }
    }

    protected void removeAccount() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        LOGGER.info("Preparing to delete account.");
        String accountName = getUserInteraction().readAccountName();
        if (getPasswordContainer().doesAccountExist(accountName)) {
            getPasswordContainer().remove(accountName);
            getPasswordContainer().save();
        } else {
            getUserInteraction().showToUser("Could not locate account " + accountName);
        }
    }

    public UserInteraction getUserInteraction() {
        return userInteraction;
    }

    public void setUserInteraction(UserInteraction userInteraction) {
        this.userInteraction = userInteraction;
    }


    public PasswordContainer getPasswordContainer() {
        return passwordContainer;
    }

    public void setPasswordContainer(PasswordContainer passwordContainer) {
        this.passwordContainer = passwordContainer;
    }
}
