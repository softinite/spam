package com.softinite.spam.encrdecr;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Responsible for loading and holding the passwords
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class PasswordContainer {

    private static final Logger LOG = Logger.getLogger(PasswordContainer.class.getName());

    private Properties properties;
    private EncryptionManager encryptionManager;
    private String password;
    private String storageFileName;

    public void init(String rootPassoword, FileProxy existingFile) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        setPassword(rootPassoword);
        setStorageFileName(existingFile.getName());
        setEncryptionManager(new EncryptionManager());
        if (existingFile.isEmpty()) {
            setProperties(new Properties());
        } else {
            decrypt(rootPassoword, existingFile);
        }
    }

    protected void decrypt(String rootPassoword, FileProxy existingFile) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException {
        setProperties(getEncryptionManager().decrypt(existingFile, rootPassoword));
    }

    public Set<String> loadKeys() {
        return (Set) getProperties().keySet();
    }

    public Properties getProperties() {
        return properties;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }

    public void addAccount(String accountName, String accountSecret) {
        getProperties().put(accountName, accountSecret);
    }

    public void save() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        getEncryptionManager().encrypt(getProperties(), getPassword(), getStorageFileName());
    }

    public void dumpToNewFile(FileProxy fProxy) throws IOException {
        fProxy.touch();
        try (PrintWriter fWriter = fProxy.loadWriter()) {
            getProperties().list(fWriter);
        }
    }

    public void importAccounts(FileProxy fProxy) throws IOException {
        Files.lines(Paths.get(fProxy.getName())).forEach(this::importLine);
    }

    protected void importLine(String line) {
        if (!StringUtils.isBlank(line)) {
            int eqPos = StringUtils.indexOf(line, "=");
            if (eqPos > 0) {
                String acctName = StringUtils.left(line, eqPos);
                String acctSecret = StringUtils.substring(line, eqPos + 1);
                LOG.info("Importing account " + acctName);
                String existingAcctWithSameName = getProperties().getProperty(acctName);
                if (existingAcctWithSameName != null) {
                    LOG.warning("Account " + acctName + " already exists.");
                    acctName += "_" + UUID.randomUUID().toString();
                    LOG.warning("Importing under the new name '" + acctName + "'");
                }
                getProperties().put(acctName, acctSecret);
            } else {
                LOG.warning("Ignoring import line '" + line + "' as it does not contain the '=' separator between account name and secret.");
            }
        }
    }

    protected EncryptionManager getEncryptionManager() {
        return encryptionManager;
    }

    protected void setEncryptionManager(EncryptionManager encryptionManager) {
        this.encryptionManager = encryptionManager;
    }

    protected String getPassword() {
        return password;
    }

    protected void setPassword(String password) {
        this.password = password;
    }

    public String getStorageFileName() {
        return storageFileName;
    }

    protected void setStorageFileName(String storageFileName) {
        this.storageFileName = storageFileName;
    }

    public String loadSecret(String accountName) {
        return getProperties().getProperty(accountName);
    }

    public void remove(String accountName) {
        getProperties().remove(accountName);
    }

    public Boolean doesAccountExist(String accountName) {
        return getProperties().containsKey(accountName);
    }

    public void modify(String accountName, String accountSecret) {
        getProperties().put(accountName, accountSecret);
    }
}
