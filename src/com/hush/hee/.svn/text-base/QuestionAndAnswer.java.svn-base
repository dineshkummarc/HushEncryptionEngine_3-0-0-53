package com.hush.hee;

import java.io.Serializable;

public class QuestionAndAnswer implements Serializable
{
	private static final long serialVersionUID = 4315716985002829370L;

	private String question;
	
	private String answer;
	
	private String[] recipients;
	
	private String answerHash;
	
	private String answerSalt;
	
	private int answerWordCount;

	/**
	 * @return Returns the answer.
	 */
	public String getAnswer()
	{
		return answer;
	}

	/**
	 * @param answer The answer to set.
	 */
	public void setAnswer(String answer)
	{
		if ( answer == null )
		{
			this.answer = answer;
			setAnswerWordCount(0);
			return;
		}
		answer = answer.trim();
		if ( ! isValidAnswer(answer) )
		{
			throw new InvalidAnswerException();
		}
		int words = 1;
		for (int i = 0; i < answer.length(); i++)
		{
			char next = answer.charAt(i);
			if (next == ' ') words++;
		}
		this.answer = answer;
		setAnswerWordCount(words);
	}

	/**
	 * @return Returns the answerHash.
	 */
	public String getAnswerHash()
	{
		if (answer == null || answer.equals(""))
			return null;
		
		if (answerHash == null)
		{
			setAnswerHash(PasswordUtils.generatePasswordHash(getEncryptionKey()));
		}

		return answerHash;
	}

	/**
	 * @return Get the encryption key
	 */
	public String getEncryptionKey()
	{
		if (answer == null || answer.equals(""))
			return null;

		return PasswordUtils.generateEncryptionKey(getAnswerSalt(), this.answer);
	}
	
	/**
	 * @param answerHash The answerHash to set.
	 */
	public void setAnswerHash(String answerHash)
	{
		this.answerHash = answerHash;
	}

	/**
	 * @return Returns the answerWordCount.
	 */
	public int getAnswerWordCount()
	{
		return answerWordCount;
	}

	/**
	 * @param answerWordCount The answerWordCount to set.
	 */
	public void setAnswerWordCount(int answerWordCount)
	{
		this.answerWordCount = answerWordCount;
	}

	/**
	 * @return Returns the answerSalt.
	 */
	public String getAnswerSalt()
	{
		if (answer == null || answer.equals(""))
			return null;

		if (answerSalt == null)
		{
			setAnswerSalt(PasswordUtils.generateAnswerSalt());
		}
		return answerSalt;
	}

	/**
	 * @param answerSalt The answerSalt to set.
	 */
	public void setAnswerSalt(String answerSalt)
	{
		this.answerSalt = answerSalt;
	}

	/**
	 * @return Returns the question.
	 */
	public String getQuestion()
	{
		return question;
	}

	/**
	 * @param question The question to set.
	 */
	public void setQuestion(String question)
	{
		if ( question != null && ! isValidQuestion(question) )
		{
			throw new InvalidQuestionException();
		}
		this.question = question;
	}

	/**
	 * Will never return null, just a 0 length array.
	 * 
	 * @return Returns the recipients.
	 */
	public String[] getRecipientAliases()
	{
		if ( recipients == null ) return new String[0];
		return recipients;
	}

	/**
	 * Will never return null, just a 0 length array.
	 * 
	 * @param recipients The recipients to set.
	 */
	public void setRecipientAliases(String[] recipients)
	{
		this.recipients = recipients;
	}
	
	public boolean isValidQuestion(String question)
	{
		return null != question && ! question.trim().equals("");
	}
	
	public boolean isValidAnswer(String answer)
	{
		return null != answer && ! PasswordUtils.canonicalizePassword(answer).equals("");
	}
}