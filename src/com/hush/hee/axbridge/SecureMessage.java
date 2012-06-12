package com.hush.hee.axbridge;

import com.hush.hee.axbridge.QuestionAndAnswer;
import com.hush.pgp.PgpConstants;
import com.hush.util.Conversions;

/**
 * This class provides the functionality of a SecureMessage in a browser-based
 * environment.
 */
public class SecureMessage
{
    private com.hush.hee.SecureMessage myDelegate;

    protected SecureMessage()
    {
        myDelegate = new com.hush.hee.SecureMessage();
    }

    protected com.hush.hee.SecureMessage getDelegate()
    {
        return myDelegate;
    }
    
    public boolean getAnonymous()
    {
        return myDelegate.getAnonymous();
    }

    public boolean getUseArmor()
    {
        return myDelegate.getUseArmor();
    }

    public String getAuthInfo()
    {
        return myDelegate.getAuthInfo();
    }
    
    public void setAuthInfo(String authInfo)
    {
        myDelegate.setAuthInfo(authInfo);
    }
    
    public String[] getCertificates()
    {
        return myDelegate.getCertificates();
    }

    public String getCharacterEncoding()
    {
        return myDelegate.getCharacterEncoding();
    }

    public String[] getDetachedSignatures()
    {
        return myDelegate.getDetachedSignatures();
    }

    public String getGeneratedPassword()
    {
        return myDelegate.getGeneratedPassword();
    }

    public String getGeneratedPasswordEncryptionKey()
    {
        return myDelegate.getGeneratedPasswordEncryptionKey();
    }

    public String getGeneratedPasswordHash()
    {
        return myDelegate.getGeneratedPasswordHash();
    }

    public String getGeneratedPasswordSalt()
    {
        return myDelegate.getGeneratedPasswordSalt();
    }

    public String getInputText()
	{
		return Conversions.byteArrayToString(myDelegate.getInputBytes(),
				getCharacterEncoding());
	}

    public String[] getInvalidSigners()
    {
        return myDelegate.getInvalidSigners();
    }

    public String getNotes()
    {
        return myDelegate.getNotes();
    }

    public String[] getOnePassSignatures()
    {
        return myDelegate.getOnePassSignatures();
    }

    public String getOutputText()
	{
		byte[] outputBytes = myDelegate.getOutputBytes();
		if (outputBytes == null)
			return null;
		// It is not currently possible to get any output
		// other than UTF8 when encrypting a message
		// See PgpMessageOutputStream
		// -sbs
		return Conversions.byteArrayToString(outputBytes,
				PgpConstants.UTF8);
	}

    public String[] getPasswords()
    {
        byte[][] passwords = myDelegate.getPasswords();
        if ( passwords == null ) return null;
        String[] passwordsStringArray = new String[passwords.length];
        for (int i = 0; i < passwords.length; i++)
        {
            passwordsStringArray[i] = new String(passwords[i]);
        }
        return passwordsStringArray;
    }

    public QuestionAndAnswer[] getQuestionsAndAnswers()
    {
    	com.hush.hee.QuestionAndAnswer[] questionsAndAnswers = myDelegate.getQuestionsAndAnswers();
		if (questionsAndAnswers == null)
		{
			return null;
		}
		QuestionAndAnswer[] wrappedQuestionsAndAnswers = new QuestionAndAnswer[questionsAndAnswers.length];
		for (int x = 0; x < questionsAndAnswers.length; x++)
		{
			wrappedQuestionsAndAnswers[x] = new QuestionAndAnswer(questionsAndAnswers[x]);
		}
    	return wrappedQuestionsAndAnswers;
    }

    public String[] getRecipientAliases()
    {
        return myDelegate.getRecipientAliases();
    }

    public String getSignerAlias()
    {
        return myDelegate.getSignerAlias();
    }

    public String[] getValidSigners()
    {
        return myDelegate.getValidSigners();
    }

    public boolean getPublicKeyEncryptionOnly()
    {
        return myDelegate.getPublicKeyEncryptionOnly();
    }

    public void setAnonymous(boolean anonymous)
    {
        myDelegate.setAnonymous(anonymous);
    }

    public void setUseArmor(boolean useArmor)
    {
        myDelegate.setUseArmor(useArmor);
    }

    public void setCharacterEncoding(String characterEncoding)
    {
        myDelegate.setCharacterEncoding(characterEncoding);
    }

    public void setGeneratedPassword(String generatedPassword)
    {
        myDelegate.setGeneratedPassword(generatedPassword);
    }

    public void setGeneratedPasswordEncryptionKey(
            String generatedPasswordEncryptionKey)
    {
        myDelegate
                .setGeneratedPasswordEncryptionKey(generatedPasswordEncryptionKey);
    }

    public void setGeneratedPasswordHash(String generatedPasswordHash)
    {
        myDelegate.setGeneratedPasswordHash(generatedPasswordHash);
    }

    public void setGeneratedPasswordSalt(String generatedPasswordSalt)
    {
        myDelegate.setGeneratedPasswordSalt(generatedPasswordSalt);
    }

    public void setInputText(String inputText)
	{
		if (inputText == null)
			myDelegate.setInputBytes(null);
		myDelegate.setInputBytes(Conversions.stringToByteArray(inputText,
				_getCharacterEncoding()));
	}

    public void setNotes(String notes)
    {
        myDelegate.setNotes(notes);
    }

    public void setPasswords(String[] passwords)
    {
    	if ( passwords == null )
    	{
    		myDelegate.setPasswords(null);
    		return;
    	}
        byte[][] passwordBytes = new byte[passwords.length][];
        for (int i = 0; i < passwords.length; i++)
        {
            passwordBytes[i] = Conversions.stringToByteArray(passwords[i],
					getCharacterEncoding());
        }
        myDelegate.setPasswords(passwordBytes);
    }

    public void setPublicKeyEncryptionOnly(boolean publicKeyEncryptionOnly)
	{
		myDelegate
				.setPublicKeyEncryptionOnly(publicKeyEncryptionOnly);
	}

    public void setQuestionsAndAnswers(QuestionAndAnswer[] questionsAndAnswers)
	{
		if (questionsAndAnswers == null)
		{
			myDelegate.setQuestionsAndAnswers(null);
			return;
		}
		com.hush.hee.QuestionAndAnswer[] unwrappedQuestionsAndAnswers = new com.hush.hee.QuestionAndAnswer[questionsAndAnswers.length];
		for (int x = 0; x < questionsAndAnswers.length; x++)
		{
			unwrappedQuestionsAndAnswers[x] = questionsAndAnswers[x].getDelegate();
		}
		myDelegate.setQuestionsAndAnswers(unwrappedQuestionsAndAnswers);
	}

    public void setRecipientAliases(String[] aliases)
    {
    	myDelegate.setRecipientAliases(aliases);
    }

    public void setSignerAlias(String signerAlias)
    {
        myDelegate.setSignerAlias(signerAlias);
    }

    public String toString()
    {
        return myDelegate.toString();
    }

    public String getFirstQuestion()
	{
		if (myDelegate.getQuestionsAndAnswers() == null
				|| myDelegate.getQuestionsAndAnswers().length == 0)
			return null;
		return myDelegate.getQuestionsAndAnswers()[0].getQuestion();
	}

	public String getFirstAnswer()
	{
		if (myDelegate.getQuestionsAndAnswers() == null
				|| myDelegate.getQuestionsAndAnswers().length == 0)
			return null;
		return myDelegate.getQuestionsAndAnswers()[0].getAnswer();
	}
	
	public String getFirstAnswerSalt()
	{
		if (myDelegate.getQuestionsAndAnswers() == null
				|| myDelegate.getQuestionsAndAnswers().length == 0)
			return null;
		return myDelegate.getQuestionsAndAnswers()[0].getAnswerSalt();
	}
    
    private String _getCharacterEncoding()
	{
		String enc = myDelegate.getCharacterEncoding();
		if (enc == null)
			throw new RuntimeException(
					"No character encoding set on SecureMessage object");
		return enc;
	}

	public String getAuthInfoEmailHeaderName()
	{
		return myDelegate.getAuthInfoEmailHeaderName();
	}

	public String getAuthInfoEmailHeaderValue()
	{
		return myDelegate.getAuthInfoEmailHeaderValue();
	}

	public boolean hasAuthInfo()
	{
		return myDelegate.hasAuthInfo();
	}
}
