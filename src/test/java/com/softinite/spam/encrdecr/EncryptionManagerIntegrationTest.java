package com.softinite.spam.encrdecr;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

/**
 * Responsible for testing EncryptionManager
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class EncryptionManagerIntegrationTest {

    public static final String DATA_FILE_NAME = "secret.spam";

    @BeforeMethod
    public void setup() {
        deleteDataFile();
    }

    @AfterMethod
    public void cleanup() {
        deleteDataFile();
    }

    protected void deleteDataFile() {
        File dataFile = new File(DATA_FILE_NAME);
        if (dataFile.exists()) {
            dataFile.delete();
        }
    }

    @Test
    public void checkEncryption() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        EncryptionManager encryptionManager = new EncryptionManager();
        Properties secret = new Properties();
        String acctName = "abc";
        String acctSecret = "mySecret";
        String password = "password";
        secret.put(acctName, acctSecret);
        secret.put("my bank", "my bank secret access codes");
        FileProxy encryptedFile = encryptionManager.encrypt(secret, password, DATA_FILE_NAME);
        String name = encryptedFile.getName();
        System.out.println("Preparing to read " + name);
        String content = new String(Files.readAllBytes(Paths.get(name)));
        System.out.println(content);
        Properties decryptedProps = encryptionManager.decrypt(encryptedFile, password);
        Assert.assertEquals(decryptedProps.getProperty(acctName), acctSecret);
    }

}
