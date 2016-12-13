package com.softinite.spam.encrdecr;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;
import java.util.Set;

/**
 * Responsible for loading and holding the passwords
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class PasswordContainer {

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
