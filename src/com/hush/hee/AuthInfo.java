package com.hush.hee;

import java.util.Vector;

import com.hush.org.apache.commons.lang.StringEscapeUtils;

public class AuthInfo
{
	public static String EMAIL_HEADER_NAME = "X-hush-password-message-auth";
	private static final String AUTHINFO = "authInfo";
	private static final String VERSION = "version";
	private static final String VERSION_NUMBER = "1.1";
	private static final String SENDER = "sender";
	private static final String PASSWORD = "password";
	private static final String PASSWORD_SALT = "passwordSalt";
	private static final String PASSWORD_HASH = "passwordHash";
	private static final String SUBJECT = "subject";
	private static final String BODY = "body";
	private static final String MESSAGEID = "messageID";
	private static final String RECIPIENT = "recipient";
	private static final String ADDRESS = "address";
	private static final String CUSTOMERID = "customerID";
	private static final String QUESTION = "question";
	private static final String ANSWERSALT = "answerSalt";
	private static final String ANSWERHASH = "answerHash";
	private static final String ANSWERWORDCOUNT = "answerWordCount";
	private static final String TYPE = "type";
	private static final String TYPE_PUBLIC_KEY = "PublicKey";
	private static final String TYPE_STORE_PASSWORD = "GeneratedPasswordStore";
	private static final String TYPE_EMAIL_PASSWORD = "GeneratedPasswordEmail";
	private static final String TYPE_QUESTION_AND_ANSWER = "QuestionAndAnswer";
	private Vector recipientFields;
	private String sender;
	
	public AuthInfo()
	{
		recipientFields = new Vector();
	}
	
	public void setSender(String sender)
	{
		this.sender = sender;
	}
	
	public void addPublicKeyRecipient(String[] emailAddress)
	{
		for (int i = 0; i < emailAddress.length; i++)
		{
			recipientFields.addElement("\t<" + RECIPIENT + " " + ADDRESS
				+ "=\"" + StringEscapeUtils.escapeXml(emailAddress[i]) + "\" " + TYPE + "=\""
				+ TYPE_PUBLIC_KEY + "\"/>\r\n");
		}
	}
	
	public void addGeneratedPasswordRecipient(String[] emailAddress, String messageID, String encryptedPassword,
			String encryptedPasswordSubject, String plaintextPassword, String passwordSalt, String passwordHash, boolean store,
			String passwordRecipient)
	{
		for (int i = 0; i < emailAddress.length; i++)
		{
			StringBuffer field = new StringBuffer();
			
			field.append("\t<" + RECIPIENT + " " + ADDRESS
					+ "=\"" + StringEscapeUtils.escapeXml(emailAddress[i])
					+ "\" " + TYPE + "=\""
					+ ( store ? TYPE_STORE_PASSWORD	: TYPE_EMAIL_PASSWORD ) + "\">\r\n");	
			
			if (store)
			{
				field.append("\t\t<" + PASSWORD + ">" + StringEscapeUtils.escapeXml(plaintextPassword) + "</" + PASSWORD + ">\r\n");
			}
			else
			{
				field.append("\t\t<" + MESSAGEID + ">" + StringEscapeUtils.escapeXml(messageID) + "</" + MESSAGEID + ">\r\n"
					+ "\t\t<" + PASSWORD + 
						( passwordRecipient == null ? "" : " " + RECIPIENT + "=\""
						+ StringEscapeUtils.escapeXml(passwordRecipient) + "\"")
					+ ">\r\n"
					+ "\t\t\t<" + SUBJECT + "><![CDATA[" + encryptedPasswordSubject + "]]></" + SUBJECT + ">\r\n"
					+ "\t\t\t<" + BODY + "><![CDATA["
					+ encryptedPassword
					+ "]]></" + BODY + ">\r\n\t\t"+ "</" + PASSWORD + ">\r\n");
			}
			field.append("\t\t<" + PASSWORD_SALT + ">" + StringEscapeUtils.escapeXml(passwordSalt) + "</" + PASSWORD_SALT + ">\r\n");
			field.append("\t\t<" + PASSWORD_HASH + ">" + StringEscapeUtils.escapeXml(passwordHash) + "</" + PASSWORD_HASH + ">\r\n");
			field.append("\t</" + RECIPIENT + ">\r\n");
			
			recipientFields.addElement(field.toString());
		}
	}
	
	public void addQuestionAndAnswerRecipient(QuestionAndAnswer questionAndAnswer)
	{
		for (int i = 0; i < questionAndAnswer.getRecipientAliases().length; i++)
		{
			recipientFields.addElement("\t<" + RECIPIENT + " " + ADDRESS
				+ "=\"" + StringEscapeUtils.escapeXml(questionAndAnswer.getRecipientAliases()[i]) + "\" " + TYPE + "=\""
				+ TYPE_QUESTION_AND_ANSWER + "\">\r\n"
				+ "\t\t<" + QUESTION + ">" + StringEscapeUtils.escapeXml(questionAndAnswer.getQuestion()) + "</" + QUESTION + ">\r\n"
				+ "\t\t<" + ANSWERSALT + ">" + StringEscapeUtils.escapeXml(questionAndAnswer.getAnswerSalt()) + "</" + ANSWERSALT + ">\r\n"
				+ "\t\t<" + ANSWERHASH + ">" + StringEscapeUtils.escapeXml(questionAndAnswer.getAnswerHash()) + "</" + ANSWERHASH + ">\r\n"
				+ "\t\t<" + ANSWERWORDCOUNT + ">" + questionAndAnswer.getAnswerWordCount() + "</" + ANSWERWORDCOUNT + ">\r\n"
				+ "\t</" + RECIPIENT + ">\r\n");
		}
	}

	public String toString()
	{
		if (recipientFields.size() == 0)
			return null;
		
		StringBuffer xml = new StringBuffer("<?xml version=\"1.0\"?>\r\n");
		xml.append("<" + AUTHINFO + " " + VERSION + "=\"" + VERSION_NUMBER + "\">\r\n");
		if (sender != null )
		{
			xml.append("\t<" + SENDER + " ");
			if (sender != null)
			{
				xml.append(ADDRESS + "=\"" + StringEscapeUtils.escapeXml(sender) + "\" ");
			}
			xml.append("/>\r\n");
		}
		for (int i = 0; i < recipientFields.size(); i++)
		{
			xml.append (recipientFields.elementAt(i));
		}
		xml.append("</" + AUTHINFO + ">");
		
		return xml.toString();
	}
}
