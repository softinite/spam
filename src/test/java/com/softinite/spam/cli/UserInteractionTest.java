package com.softinite.spam.cli;

import org.testng.annotations.Test;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

/**
 * Responsible for testing UserInteraction
 * Created by Sergiu Ivasenco on 18/12/16.
 */
public class UserInteractionTest {

    @Test
    public void accountNameReturnedWhenNameIsNotBlank() {
        UserInteraction userInteraction = spy(new UserInteraction());
        String expectedName = "Joe Doe";

        doReturn(expectedName).when(userInteraction).readLine();

        assertEquals(userInteraction.readAccountName(), expectedName);
    }

    @Test
    public void readAccountNameThrowsExceptionForBlankName() {
        validateBlankAcctNameValue(null);
        validateBlankAcctNameValue("");
        validateBlankAcctNameValue(" ");
        validateBlankAcctNameValue("        ");
    }

    protected void validateBlankAcctNameValue(String blankAccountName) {
        UserInteraction userInteraction = spy(new UserInteraction());

        doReturn(blankAccountName).when(userInteraction).readLine();

        try {
            String acctName = userInteraction.readAccountName();
            fail("Exception not thrown, but account=" + acctName + " has been read.");
        } catch (RuntimeException re) {
            assertEquals(re.getMessage(), UserInteraction.BLANK_NAME_NOT_ALLOWED);
        }
    }

}
