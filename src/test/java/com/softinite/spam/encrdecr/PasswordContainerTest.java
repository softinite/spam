package com.softinite.spam.encrdecr;

import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.mockito.Mockito.*;

/**
 * Responsible for testing PasswordContainer
 * Created by Sergiu Ivasenco on 06/12/16.
 */
public class PasswordContainerTest {

    @Test
    public void initMethodDoesNotCallDecryptForEmptyFiles() throws NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, IOException {
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
