package com.softinite.spam.encrdecr;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Responsible for testing PasswordContainer
 * Created by Sergiu Ivasenco on 06/12/16.
 */
public class PasswordContainerTest {

    @Test
    public void verifyRemoveAccount() {
        PasswordContainer container = new PasswordContainer();
        container.setProperties(new Properties());

        container.addAccount("acct1", "secret1");
        container.addAccount("acct2", "secret2");
        container.addAccount("acct3", "secret3");

        assertTrue(container.doesAccountExist("acct1"));
        assertTrue(container.doesAccountExist("acct2"));
        assertTrue(container.doesAccountExist("acct3"));

        container.remove("acct1");

        assertFalse(container.doesAccountExist("acct1"));
        assertTrue(container.doesAccountExist("acct2"));
        assertTrue(container.doesAccountExist("acct3"));

        container.remove(new String("acct2"));

        assertFalse(container.doesAccountExist("acct2"));
        assertTrue(container.doesAccountExist("acct3"));
    }

    @Test
    public void verifyAccountExists() {
        PasswordContainer container = new PasswordContainer();
        container.setProperties(new Properties());

        container.addAccount("acct1", "secret1");
        container.addAccount("acct2", "secret2");

        assertTrue(container.doesAccountExist("acct1"));
        assertTrue(container.doesAccountExist(new String("acct1")));
        assertFalse(container.doesAccountExist("acct3"));
    }

    @Test
    public void initMethodDoesNotCallDecryptForEmptyFiles() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        PasswordContainer passwordContainer = spy(PasswordContainer.class);
        FileProxy fileProxy = mock(FileProxy.class);
        String password = "myPassword";

        when(fileProxy.isEmpty()).thenReturn(Boolean.TRUE);
        when(fileProxy.getName()).thenReturn("empty.file");
        doNothing().when(passwordContainer).decrypt(password, fileProxy);

        passwordContainer.init(password, fileProxy);

        verify(passwordContainer, times(0)).decrypt(password, fileProxy);
    }

}
