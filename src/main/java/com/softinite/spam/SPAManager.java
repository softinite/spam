package com.softinite.spam;

import com.beust.jcommander.JCommander;
import com.softinite.spam.cli.CLIParameters;
import com.softinite.spam.cli.UserInteraction;
import com.softinite.spam.encrdecr.FileProxy;
import com.softinite.spam.encrdecr.PasswordContainer;
import lombok.Data;
import lombok.extern.java.Log;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Responsible for starting the application
 * Created by Sergiu Ivasenco on 01/12/16.
 */
@Log
@Data
public class SPAManager {

    public static final String CMD_LINE_SYNTAX = "java -jar com.softinite.spam-1.1-SNAPSHOT.jar <OPTIONS>";
    public static final String ACCT_ALREADY_EXISTS = "Account already exists ";
    protected static final String ACCT_NOT_FOUND_MSG = "Could not locate account ";
    private UserInteraction userInteraction;
    private PasswordContainer passwordContainer;
    private JCommander commandParser;

    public static void main(String[] args) throws Exception {
        log.info("Password manager has been started.");
        SPAManager manager = new SPAManager();
        manager.setPasswordContainer(new PasswordContainer());
        manager.setUserInteraction(new UserInteraction());

        CLIParameters params = new CLIParameters();
        manager.setCommandParser(new JCommander(params, args));

        log.info("Executing selected command.");
        manager.execute(params);
    }

    public void showHelp() {
        log.info("Displaying help options to user.");
        getCommandParser().setProgramName("Simple PAssword Manager", CMD_LINE_SYNTAX);
        getCommandParser().usage();
    }

    public void execute(CLIParameters params) throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, InvalidCipherTextException {
        log.info("Processing file argument ");
        if (StringUtils.isNotBlank(params.getFile())) {
            log.info("File option found.");
            executeWithFileName(params.getFile(), params);
        } else {
            log.info("File option not found.");
            showHelp();
        }
    }

    public void executeWithFileName(String fileName, CLIParameters params) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, InvalidCipherTextException {
        log.info("Loading password file object " + fileName);
        FileProxy file = loadPasswordFileObject(fileName);
        executeWithFile(params, file);
    }

    protected void executeWithFile(CLIParameters params, FileProxy file) throws IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, InvalidCipherTextException {
        if (file.exists()) {
            log.info("File exists.");
            String rootPassoword = getUserInteraction().readSPAMPassoword();
            getPasswordContainer().init(rootPassoword, file);
            executeUserCommand(params);
        } else if (params.getCreate()) {
            log.info("Creating the file.");
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

    protected void executeUserCommand(CLIParameters params) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        if (params.getList()) {
            listAllAccounts();
        } else if (params.getNewAcct()) {
            addAccount();
        } else if (params.getShow()) {
            showSecret();
        } else if (params.getUpdate()) {
            modifySecret();
        } else if (params.getDelete()) {
            removeAccount();
        } else if (StringUtils.isNotBlank(params.getDump())) {
            dumpAccounts(params.getDump());
        } else if (StringUtils.isNotBlank(params.getImportFile())) {
            importAccounts(params.getImportFile());
        } else if (params.getRename()) {
            renameAccount();
        } else if (params.getSearch()) {
            searchAccounts();
        } else if (StringUtils.isNotBlank(params.getMergeFile())) {
            mergeFiles(params.getMergeFile());
        }
    }

    protected void createFile(FileProxy targetFile) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        String rootPassword = getUserInteraction().readSPAMPassoword();
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
        log.info("Listing all the accounts.");
        getUserInteraction().showSetToUser(getPasswordContainer().loadKeys());
    }

    protected void addAccount() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        log.info("Adding new account to manager's database.");
        String accountName = getUserInteraction().readAccountName();
        addAccount(accountName);
    }

    protected void addAccount(String accountName) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        log.info("Reading secret for account=" + accountName);
        String accountSecret = getUserInteraction().readAccountSecret();
        getPasswordContainer().addAccount(accountName, accountSecret);
        getPasswordContainer().save();
    }

    protected void showSecret() {
        log.info("Preparing to show the secret for an account.");
        String accountName = getUserInteraction().readAccountName();
        String secret = getPasswordContainer().loadSecret(accountName);
        if (secret == null) {
            getUserInteraction().showErrorToUser(ACCT_NOT_FOUND_MSG + accountName);
        } else {
            getUserInteraction().showToUser(secret);
        }
    }

    protected void modifySecret() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        log.info("Preparing to modify an account.");
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

    protected void removeAccount() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        log.info("Preparing to delete account.");
        String accountName = getUserInteraction().readAccountName();
        if (getPasswordContainer().doesAccountExist(accountName)) {
            getPasswordContainer().remove(accountName);
            getPasswordContainer().save();
        } else {
            getUserInteraction().showToUser("Could not locate account " + accountName);
        }
    }

    protected void dumpAccounts(String fileName) throws IOException {
        log.info("Preparing to dump information about all the accounts.");
        if (StringUtils.isBlank(fileName)) {
            getUserInteraction().showErrorToUser("Cannot accept blank file name for dumping accounts.");
        } else {
            FileProxy fProxy = new FileProxy();
            fProxy.setInternal(new File(fileName));
            if (fProxy.exists()) {
                getUserInteraction().showErrorToUser("It seems that the file " + fileName + " already exists.");
            } else {
                getPasswordContainer().dumpToNewFile(fProxy);
            }
        }
    }

    protected void importAccounts(String fileName) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        log.info("Preparing to import accounts from a plaintext file.");
        if (StringUtils.isBlank(fileName)) {
            getUserInteraction().showErrorToUser("Cannot accept blank file name for importing accounts.");
        } else {
            FileProxy fProxy = new FileProxy();
            fProxy.setInternal(new File(fileName));
            if (fProxy.exists()) {
                getPasswordContainer().importAccounts(fProxy);
                getPasswordContainer().save();
            } else {
                getUserInteraction().showErrorToUser("Could not locate file " + fileName + " for importing accounts.");
            }
        }
    }


    protected void renameAccount() throws IOException, NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException {
        log.info("Preparing to rename an account.");
        String oldAccountName = getUserInteraction().readAccountName();
        if (getPasswordContainer().doesAccountExist(oldAccountName)) {
            getUserInteraction().showToUser("Account " + oldAccountName + " has been located. Please enter the new name.");
            String newAccountName = readAndValidateNewName();
            getPasswordContainer().rename(oldAccountName, newAccountName);
            getPasswordContainer().save();
        } else {
            getUserInteraction().showErrorToUser("Could not find account with name " + oldAccountName + ".");
        }
    }

    protected void searchAccounts() {
        log.info("Preparing to search for accounts.");
        String searchPattern = getUserInteraction().readSearchPattern();
        getPasswordContainer()
                .loadKeys()
                .stream()
                .filter(accountName -> StringUtils.containsIgnoreCase(accountName, searchPattern))
                .sorted()
                .forEach(acctName -> getUserInteraction().showToUser(acctName));
    }

    protected void mergeFiles(String mergeFile) throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidCipherTextException, IOException, NoSuchProviderException, InvalidKeyException {
        log.info("Preparing to merge accounts from two files.");
        PasswordContainer secondPasswordContainer = loadPasswordContainer(mergeFile);
        getPasswordContainer().mergeFrom(secondPasswordContainer);
        getPasswordContainer().save();
    }

    private PasswordContainer loadPasswordContainer(String mergeFile) throws IllegalBlockSizeException, NoSuchAlgorithmException, IOException, InvalidCipherTextException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        FileProxy mergeFileProxy = loadPasswordFileObject(mergeFile);
        PasswordContainer pc = new PasswordContainer();
        String mergeFilePwd = getUserInteraction().readSPAMPassoword("Please specify SPAM password for the merge file.");
        pc.init(mergeFilePwd, mergeFileProxy);
        return pc;
    }

    protected String readAndValidateNewName() {
        String newName = getUserInteraction().readAccountName();
        if (getPasswordContainer().doesAccountExist(newName)) {
            throw new RuntimeException(ACCT_ALREADY_EXISTS + newName);
        }
        return newName;
    }

}
