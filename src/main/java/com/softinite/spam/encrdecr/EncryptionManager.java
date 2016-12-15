package com.softinite.spam.encrdecr;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * Responsible for encrypting and decrypting files.
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class EncryptionManager {

    private static final Logger LOGGER = Logger.getLogger(EncryptionManager.class.getName());
    public static final Charset UTF8 = Charset.forName("UTF-8");

    public FileProxy encrypt(Properties privateContent, String password, String fileName) throws IOException, InvalidCipherTextException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        LOGGER.info("Preparing to encrypt content.");
        FileProxy encrypted = new FileProxy();
        encrypted.setInternal(new File(fileName));
        BufferedBlockCipher cipher = buildCipher(password, Boolean.TRUE);
        byte[] input = loadPlainText(privateContent);
        byte[] outputBytes = performCryptographicOperation(cipher, input);
        encrypted.write(outputBytes);
        return encrypted;
    }

    protected byte[] performCryptographicOperation(BufferedBlockCipher cipher, byte[] input) throws InvalidCipherTextException {
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int outputLen = cipher.processBytes(input, 0, input.length, cipherText, 0);
        cipher.doFinal(cipherText, outputLen);
        return cipherText;
    }

    protected BufferedBlockCipher buildCipher(String password, Boolean forEncryption) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        BlockCipher engine = new AESEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine));

        byte []key = generateKey(password);

        cipher.init(forEncryption, new KeyParameter(key));
        return cipher;
    }

    private byte[] generateKey(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(password.getBytes(UTF8));
        byte[] keyBytes = new byte[32];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        return keyBytes;
    }

    private byte[] loadPlainText(Properties privateContent) {
        if (privateContent != null) {
            return privateContent
                    .entrySet()
                    .stream()
                    .reduce("", (accStr, entry) -> accStr + entry.getKey() + "=" + entry.getValue() + System.lineSeparator(), (s1, s2) -> s1 + s2)
                    .getBytes(UTF8);
        }
        return new byte[]{};
    }

    public Properties decrypt(FileProxy encryptedFile, String password) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidCipherTextException {
        LOGGER.info("Preparing to decrypt content.");
        BufferedBlockCipher cipher = buildCipher(password, Boolean.FALSE);
        byte[] encryptedContent = Files.readAllBytes(Paths.get(encryptedFile.getName()));

        byte[] outputBytes = performCryptographicOperation(cipher, encryptedContent);

        String decryptedStr = new String(outputBytes);
        String[] pairs = StringUtils.split(decryptedStr, "\n");
        Properties props = new Properties();
        for (String pair : pairs) {
            if (StringUtils.isNotBlank(pair)) {
                int splitIdx = pair.indexOf("=");
                if (splitIdx > 0) {
                    String key = StringUtils.left(pair, splitIdx);
                    String value = StringUtils.substring(pair, splitIdx + 1);
                    props.put(key, value);
                } else {
                    LOGGER.warning("Invalid entry " + pair);
                }
            }
        }
        return props;
    }

}
