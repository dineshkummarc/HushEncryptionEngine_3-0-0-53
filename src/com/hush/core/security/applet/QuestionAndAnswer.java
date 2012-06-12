package com.hush.core.security.applet;

import com.hush.util.Conversions2;

public class QuestionAndAnswer
{
	com.hush.hee.QuestionAndAnswer myDelegate;
	
	protected QuestionAndAnswer()
	{
		myDelegate = new com.hush.hee.QuestionAndAnswer();
	}
	
	protected QuestionAndAnswer(com.hush.hee.QuestionAndAnswer delegate)
	{
		myDelegate = delegate;
	}
	
    protected com.hush.hee.QuestionAndAnswer getDelegate()
    {
        return myDelegate;
    }

	public String getAnswer()
	{
		return myDelegate.getAnswer();
	}

	public String getAnswerHash()
	{
		return myDelegate.getAnswerHash();
	}

	public String getAnswerSalt()
	{
		return myDelegate.getAnswerSalt();
	}

	public int getAnswerWordCount()
	{
		return myDelegate.getAnswerWordCount();
	}

	public String getEncryptionKey()
	{
		return myDelegate.getEncryptionKey();
	}

	public String getQuestion()
	{
		return myDelegate.getQuestion();
	}

	public String[] getRecipientAliases()
	{
		return myDelegate.getRecipientAliases();
	}

	public void setAnswer(String answer)
	{
		myDelegate.setAnswer(answer);
	}

	public void setAnswerHash(String answerHash)
	{
		myDelegate.setAnswerHash(answerHash);
	}

	public void setAnswerSalt(String answerSalt)
	{
		myDelegate.setAnswerSalt(answerSalt);
	}

	public void setAnswerWordCount(int answerWordCount)
	{
		myDelegate.setAnswerWordCount(answerWordCount);
	}

	public void setQuestion(String question)
	{
		myDelegate.setQuestion(question);
	}

	public void setRecipientAliases(String recipients)
	{
		if ( recipients == null ) myDelegate.setRecipientAliases(null);
        myDelegate.setRecipientAliases(Conversions2.stringToArray(recipients, ",", false));
	}

	public String toString()
	{
		return myDelegate.toString();
	}

}
