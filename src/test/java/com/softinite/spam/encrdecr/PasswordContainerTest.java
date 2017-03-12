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
import static org.testng.Assert.*;

/**
 * Responsible for testing PasswordContainer
 * Created by Sergiu Ivasenco on 06/12/16.
 */
public class PasswordContainerTest {

    @Test
    public void verifyMergeAccounts() {
        PasswordContainer container = spy(new PasswordContainer());
        container.setProperties(new Properties());
        PasswordContainer anotherContainer = new PasswordContainer();
        anotherContainer.setProperties(new Properties());

        String acct1 = "acct1";
        String secret1 = "secret1";
        String acct2 = "acct2";
        String secret2 = "secret2";
        String acct3 = "acct3";
        String secret3 = "secret3";
        String acct4 = "acct4";
        String secret4 = "secret4";
        String secret5 = "secret5";

        container.addAccount(acct1, secret1);
        container.addAccount(acct2, secret2);
        container.addAccount(acct3, secret3);

        anotherContainer.addAccount(acct4, secret4);
        anotherContainer.addAccount(acct2, secret2);
        anotherContainer.addAccount(acct3, secret5);

        String uniqueSuffix = "123";
        doReturn(uniqueSuffix).when(container).generateUniqueSuffix();

        container.mergeFrom(anotherContainer);

        assertEquals(container.getProperties().size(), 5);
        assertEquals(container.getProperties().getProperty(acct1), secret1);
        assertEquals(container.getProperties().getProperty(acct2), secret2);
        assertEquals(container.getProperties().getProperty(acct3), secret3);
        assertEquals(container.getProperties().getProperty(acct4), secret4);
        assertEquals(container.getProperties().getProperty(acct3 + "_" + uniqueSuffix), secret5);
    }

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
