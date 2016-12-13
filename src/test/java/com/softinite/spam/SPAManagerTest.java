package com.softinite.spam;

import com.softinite.spam.cli.SpamCLIOptions;
import com.softinite.spam.cli.UserInteraction;
import com.softinite.spam.encrdecr.FileProxy;
import com.softinite.spam.encrdecr.PasswordContainer;
import org.apache.commons.cli.CommandLine;
import org.mockito.Mock;
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
import static org.testng.Assert.fail;

/**
 * Responsible for testing SPAManager
 * Created by Sergiu Ivasenco on 03/12/16.
 */
public class SPAManagerTest {

    private static final Logger LOG = Logger.getLogger(SPAManagerTest.class.getName());

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
    public void createFileDoesNotSaveButThrowsExceptionWhenPasswordConfirmationDoesNotMatch() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
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
    public void ifDeleteOptionIsPassedThenRemoveAccountCallIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        CommandLine cmd = spy(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.DELETE.getName())).thenReturn(Boolean.TRUE);
        doNothing().when(manager).removeAccount();

        manager.executeUserCommand(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.DELETE.getName());
        verify(manager, times(1)).removeAccount();
    }

    @Test
    public void ifUpdateOptionIsPassedThenModifySecretCallIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        CommandLine cmd = spy(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.UPDATE.getName())).thenReturn(Boolean.TRUE);
        doNothing().when(manager).modifySecret();

        manager.executeUserCommand(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.UPDATE.getName());
        verify(manager, times(1)).modifySecret();
    }

    @Test
    public void ifShowOptionIsPassedThenDisplaySecretCallIsInvoked() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        CommandLine cmd = spy(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.SHOW.getName())).thenReturn(Boolean.TRUE);
        doNothing().when(manager).showSecret();

        manager.executeUserCommand(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.SHOW.getName());
        verify(manager, times(1)).showSecret();
    }

    @Test
    public void ifAddOptionIsPassedThenNewAccountCallIsInvoked() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        CommandLine cmd = spy(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.NEW_ACCT.getName())).thenReturn(Boolean.TRUE);
        doNothing().when(manager).addAccount();

        manager.executeUserCommand(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.NEW_ACCT.getName());
        verify(manager, times(1)).addAccount();
    }

    @Test
    public void ifListCommandIsPassedThenCallListFunction() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {
        CommandLine cmd = mock(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.LIST_ACCTS_NAMES.getName())).thenReturn(Boolean.TRUE);
        doNothing().when(manager).listAllAccounts();

        manager.executeUserCommand(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.LIST_ACCTS_NAMES.getName());
        verify(manager, times(1)).listAllAccounts();
    }

    @Test
    public void ifFileDoesNotExistButCreateOptionIsPassedThenCreateTheFile() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        CommandLine cmd = mock(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);
        FileProxy targetFile = mock(FileProxy.class);

        when(cmd.hasOption(SpamCLIOptions.FILE.getName())).thenReturn(Boolean.TRUE);
        when(manager.loadPasswordFileObject("myFile")).thenReturn(targetFile);
        when(targetFile.exists()).thenReturn(Boolean.FALSE);
        when(cmd.hasOption(SpamCLIOptions.CREATE.getName())).thenReturn(Boolean.TRUE);
        doNothing().when(manager).createFile(targetFile);

        manager.executeWithFile(cmd, targetFile);

        verify(targetFile, times(1)).exists();
        verify(cmd, times(1)).hasOption(SpamCLIOptions.CREATE.getName());
        verify(manager, times(1)).createFile(targetFile);
    }

    @Test
    public void ifFileOptionPresentThenHelpIsNotDisplayed() throws IOException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        CommandLine cmd = mock(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);
        String fileName = "myFile";

        when(cmd.hasOption(SpamCLIOptions.FILE.getName())).thenReturn(Boolean.TRUE);
        when(cmd.getOptionValue(SpamCLIOptions.FILE.getName())).thenReturn(fileName);
        doNothing().when(manager).executeWithFileName(fileName, cmd);
        doNothing().when(manager).showHelp();

        manager.execute(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.FILE.getName());
        verify(manager, times(0)).showHelp();
        verify(manager, times(1)).executeWithFileName(fileName, cmd);
    }

    @Test
    public void ifHelpOptionPresentThenHelpFunctionalityIsInvoked() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        CommandLine cmd = mock(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.FILE.getName())).thenReturn(Boolean.FALSE);
        doNothing().when(manager).showHelp();

        manager.execute(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.FILE.getName());
        verify(manager, times(1)).showHelp();
    }

    @Test
    public void ifNoOptionPresentThenHelpFunctionalityIsInvoked() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        CommandLine cmd = mock(CommandLine.class);
        SPAManager manager = spy(SPAManager.class);

        when(cmd.hasOption(SpamCLIOptions.FILE.getName())).thenReturn(Boolean.FALSE);
        doNothing().when(manager).showHelp();

        manager.execute(cmd);

        verify(cmd, times(1)).hasOption(SpamCLIOptions.FILE.getName());
        verify(manager, times(1)).showHelp();
    }

}
