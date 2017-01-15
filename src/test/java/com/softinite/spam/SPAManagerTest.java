package com.softinite.spam;

import com.softinite.spam.cli.CLIParameters;
import com.softinite.spam.cli.UserInteraction;
import com.softinite.spam.encrdecr.FileProxy;
import com.softinite.spam.encrdecr.PasswordContainer;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;
import java.util.logging.Logger;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

/**
 * Responsible for testing SPAManager
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class SPAManagerTest {

    private static final Logger LOG = Logger.getLogger(SPAManagerTest.class.getName());

    private CLIParameters params;
    
    @BeforeMethod
    public void beforeMethod() {
        params = new CLIParameters();
    }
    
    @Test
    public void ifSearchOptionIsPassedThenSearchAccountsIsInvoked() throws IOException, NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException {
        params.setSearch(Boolean.TRUE);
        SPAManager manager = spy(SPAManager.class);

        doNothing().when(manager).searchAccounts();

        manager.executeUserCommand(params);

        verify(manager, times(1)).searchAccounts();
    }

    @Test
    public void readAndValidateNewNameReturnsCorrectlyForNonExistingAccount() {
        SPAManager manager = new SPAManager();
        UserInteraction userInteraction = mock(UserInteraction.class);
        PasswordContainer passwordContainer = mock(PasswordContainer.class);
        manager.setPasswordContainer(passwordContainer);
        manager.setUserInteraction(userInteraction);

        String injectedName = "bankAccount";

        when(userInteraction.readAccountName()).thenReturn(injectedName);
        when(passwordContainer.doesAccountExist(injectedName)).thenReturn(Boolean.FALSE);

        String newName = manager.readAndValidateNewName();
        assertEquals(newName, injectedName);
    }

    @Test
    public void readAndValidateNewNameThrowsExceptionForExistingName() {
        SPAManager manager = new SPAManager();
        UserInteraction userInteraction = mock(UserInteraction.class);
        PasswordContainer passwordContainer = mock(PasswordContainer.class);
        manager.setPasswordContainer(passwordContainer);
        manager.setUserInteraction(userInteraction);

        String injectedName = "bankAccount";

        when(userInteraction.readAccountName()).thenReturn(injectedName);
        when(passwordContainer.doesAccountExist(injectedName)).thenReturn(Boolean.TRUE);

        try {
            String newName = manager.readAndValidateNewName();
            fail("Expected exception, but got " + newName + " instead.");
        } catch (RuntimeException e) {
            assertEquals(e.getMessage(), SPAManager.ACCT_ALREADY_EXISTS + injectedName);
        }
    }

    @Test
    public void ifRenameOptionIsPassedThenRenameAccountIsInvoked() throws IOException, NoSuchAlgorithmException, InvalidCipherTextException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException {
        params.setRename(Boolean.TRUE);
        SPAManager manager = spy(SPAManager.class);

        doNothing().when(manager).renameAccount();

        manager.executeUserCommand(params);

        verify(manager, times(1)).renameAccount();
    }

    @Test
    public void ifImportOptionIsPassedThenimportAccountsIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);
        String fileName = "abc.txt";
        params.setImportFile(fileName);
        
        doNothing().when(manager).importAccounts(fileName);

        manager.executeUserCommand(params);

        verify(manager, times(1)).importAccounts(fileName);
    }

    @Test
    public void ifDumpOptionIsPassedThenDumpAccountsIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);
        String fileName = "abc.txt";

        params.setDump(fileName);        
        doNothing().when(manager).dumpAccounts(fileName);

        manager.executeUserCommand(params);

        verify(manager, times(1)).dumpAccounts(fileName);
    }

    @Test
    public void showSecretIfAccountNotFoundThenDisplayAppropriateError() {
        SPAManager manager = spy(SPAManager.class);
        UserInteraction userInteraction = mock(UserInteraction.class);
        manager.setUserInteraction(userInteraction);
        PasswordContainer container = new PasswordContainer();
        container.setProperties(new Properties());
        manager.setPasswordContainer(container);

        String acctName = "abc";
        when(userInteraction.readAccountName()).thenReturn(acctName);
        doNothing().when(userInteraction).showErrorToUser(SPAManager.ACCT_NOT_FOUND_MSG + acctName);

        manager.showSecret();

        verify(userInteraction, times(1)).showErrorToUser(SPAManager.ACCT_NOT_FOUND_MSG + acctName);
        verify(userInteraction, times(0)).showToUser(null);
    }

    @Test
    public void createFileDoesNotSaveButThrowsExceptionWhenPasswordConfirmationDoesNotMatch() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);
        UserInteraction userInteraction = mock(UserInteraction.class);
        manager.setUserInteraction(userInteraction);
        FileProxy fProxy = mock(FileProxy.class);

        when(userInteraction.readRootPassoword()).thenReturn("abc");
        when(userInteraction.readPasswordConfirmation()).thenReturn("abC");

        try {
            manager.createFile(fProxy);
            fail("Runtime exception should have been thrown because passwords do not match.");
        } catch (RuntimeException re) {
            LOG.info("Expected exception caught. " + re.getMessage());
        }

        verify(fProxy, times(0)).touch();
    }

    @Test
    public void ifDeleteOptionIsPassedThenRemoveAccountCallIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);
        params.setDelete(Boolean.TRUE);

        doNothing().when(manager).removeAccount();

        manager.executeUserCommand(params);

        verify(manager, times(1)).removeAccount();
    }

    @Test
    public void ifUpdateOptionIsPassedThenModifySecretCallIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);

        params.setUpdate(Boolean.TRUE);
        doNothing().when(manager).modifySecret();

        manager.executeUserCommand(params);

        verify(manager, times(1)).modifySecret();
    }

    @Test
    public void ifShowOptionIsPassedThenDisplaySecretCallIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);

        params.setShow(Boolean.TRUE);
        doNothing().when(manager).showSecret();

        manager.executeUserCommand(params);

        verify(manager, times(1)).showSecret();
    }

    @Test
    public void ifAddOptionIsPassedThenNewAccountCallIsInvoked() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);

        params.setNewAcct(Boolean.TRUE);
        doNothing().when(manager).addAccount();

        manager.executeUserCommand(params);

        verify(manager, times(1)).addAccount();
    }

    @Test
    public void ifListCommandIsPassedThenCallListFunction() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);

        params.setList(Boolean.TRUE);
        doNothing().when(manager).listAllAccounts();

        manager.executeUserCommand(params);

        verify(manager, times(1)).listAllAccounts();
    }

    @Test
    public void ifFileDoesNotExistButCreateOptionIsPassedThenCreateTheFile() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);
        FileProxy targetFile = mock(FileProxy.class);

        String fileName = "myFile";
        params.setFile(fileName);
        params.setCreate(Boolean.TRUE);

        when(manager.loadPasswordFileObject(fileName)).thenReturn(targetFile);
        when(targetFile.exists()).thenReturn(Boolean.FALSE);
        doNothing().when(manager).createFile(targetFile);

        manager.executeWithFile(params, targetFile);

        verify(targetFile, times(1)).exists();
        verify(manager, times(1)).createFile(targetFile);
    }

    @Test
    public void ifFileOptionPresentThenHelpIsNotDisplayed() throws IOException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);
        String fileName = "myFile";

        params.setFile(fileName);

        doNothing().when(manager).executeWithFileName(fileName, params);
        doNothing().when(manager).showHelp();

        manager.execute(params);

        verify(manager, times(0)).showHelp();
        verify(manager, times(1)).executeWithFileName(fileName, params);
    }

    @Test
    public void ifHelpOptionPresentThenHelpFunctionalityIsInvoked() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);

        params.setHelp(Boolean.TRUE);
        doNothing().when(manager).showHelp();

        manager.execute(params);

        verify(manager, times(1)).showHelp();
    }

    @Test
    public void ifNoOptionPresentThenHelpFunctionalityIsInvoked() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        SPAManager manager = spy(SPAManager.class);

        doNothing().when(manager).showHelp();

        manager.execute(params);

        verify(manager, times(1)).showHelp();
    }

}
