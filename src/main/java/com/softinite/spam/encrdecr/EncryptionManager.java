package com.softinite.spam.encrdecr;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Responsible for encrypting and decrypting files.
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class EncryptionManager {

    private static final Logger LOGGER = Logger.getLogger(EncryptionManager.class.getName());

    public FileProxy encrypt(Properties privateContent, String password, String fileName) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        FileProxy encrypted = new FileProxy();
        encrypted.setInternal(new File(fileName));
        Cipher cipher = buildCipher(password, Cipher.ENCRYPT_MODE);
        encrypted.write(cipher.doFinal(loadPlainText(privateContent)));
        return encrypted;
    }

    protected Cipher buildCipher(String password, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Cipher cipher = Cipher.getInstance("AES", provider);
        Key key = buildKey(password.toCharArray(), provider);
        try {
            cipher.init(mode, key);
        } catch (InvalidKeyException ike) {
            LOGGER.log(Level.SEVERE, "Please install JCE as indicated here -> http://help.boomi.com/atomsphere/GUID-D7FA3445-6483-45C5-85AD-60CA5BB15719.html", ike);
            throw new RuntimeException(ike);
        }
        return cipher;
    }

    private byte[] loadPlainText(Properties privateContent) {
        if (privateContent != null) {
            return privateContent
                    .entrySet()
                    .stream()
                    .reduce("", (accStr, entry) -> accStr + entry.getKey() + "=" + entry.getValue() + System.lineSeparator(), (s1, s2) -> s1 + s2)
                    .getBytes();
        }
        return new byte[]{};
    }

    public Properties decrypt(FileProxy encryptedFile, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = buildCipher(password, Cipher.DECRYPT_MODE);
        byte[] encryptedContent = Files.readAllBytes(Paths.get(encryptedFile.getName()));
        String decryptedStr = new String(cipher.doFinal(encryptedContent));
        String[] pairs = StringUtils.split(decryptedStr, "\n");
        Properties props = new Properties();
        for (String pair : pairs) {
            int splitIdx = pair.indexOf("=");
            String key = StringUtils.left(pair, splitIdx);
            String value = StringUtils.substring(pair, splitIdx + 1);
            props.put(key, value);
        }
        return props;
    }

    private Key buildKey(char[] password, BouncyCastleProvider provider) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digester = MessageDigest.getInstance("SHA-256", provider);
        digester.update(String.valueOf(password).getBytes("UTF-8"));
        byte[] key = digester.digest();
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        return spec;
    }

}
