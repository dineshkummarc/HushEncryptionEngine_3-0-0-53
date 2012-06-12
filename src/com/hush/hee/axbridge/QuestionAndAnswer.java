package com.hush.hee.axbridge;

public class QuestionAndAnswer
{
	private com.hush.hee.QuestionAndAnswer delegate;

	protected QuestionAndAnswer(com.hush.hee.QuestionAndAnswer delegate)
	{
		this.delegate = delegate;
	}

	public String getAnswer()
	{
		return delegate.getAnswer();
	}

	public String getAnswerHash()
	{
		return delegate.getAnswerHash();
	}

	public String getAnswerSalt()
	{
		return delegate.getAnswerSalt();
	}

	public int getAnswerWordCount()
	{
		return delegate.getAnswerWordCount();
	}

	public String getEncryptionKey()
	{
		return delegate.getEncryptionKey();
	}

	public String getQuestion()
	{
		return delegate.getQuestion();
	}

	public String[] getRecipientAliases()
	{
		return delegate.getRecipientAliases();
	}

	public boolean isValidAnswer(String answer)
	{
		return delegate.isValidAnswer(answer);
	}

	public boolean isValidQuestion(String question)
	{
		return delegate.isValidQuestion(question);
	}

	public void setAnswer(String answer)
	{
		delegate.setAnswer(answer);
	}

	public void setAnswerHash(String answerHash)
	{
		delegate.setAnswerHash(answerHash);
	}

	public void setAnswerSalt(String answerSalt)
	{
		delegate.setAnswerSalt(answerSalt);
	}

	public void setAnswerWordCount(int answerWordCount)
	{
		delegate.setAnswerWordCount(answerWordCount);
	}

	public void setQuestion(String question)
	{
		delegate.setQuestion(question);
	}

	public void setRecipientAliases(String[] recipients)
	{
		delegate.setRecipientAliases(recipients);
	}
	
	protected com.hush.hee.QuestionAndAnswer getDelegate()
	{
		return delegate;
	}
}
