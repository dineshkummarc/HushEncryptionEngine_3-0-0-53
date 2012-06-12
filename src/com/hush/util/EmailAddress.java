/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.util;

import java.io.Serializable;
import java.util.Enumeration;
import java.util.Vector;

/**
 * A class for parsing an email address into it's components.
 */
public class EmailAddress implements Serializable
{
	private static final long serialVersionUID = 6084165620065927259L;
	private String emailAddress;
	private String nickName;

	/**
	 * Default constructor.
	 */
	public EmailAddress()
	{
	}

	public String getEmailAddress()
	{
		String sTemp = new String();
		int iRight;
		int iLeft;

		sTemp = emailAddress;

		iLeft = emailAddress.indexOf((int) '<');

		if (iLeft >= 0)
		{
			//
			// Check for the Right side bracket
			iRight = sTemp.indexOf((int) '>');

			if (iRight >= iLeft)
			{
				// Either the bracket wasnt found or else its not in the correct
				sTemp = sTemp.substring(iLeft + 1, iRight);
			}
		}

		//
		// < > Have been removed
		//
		// Ensure that we dont have a domain included
		iRight = sTemp.indexOf((int) '/');

		if (iRight >= 0)
		{
			iRight++;

			int iLen = sTemp.length();

			if (iRight < iLen)
			{
				sTemp = sTemp.substring(iRight, iLen);
			}
		}

		return sTemp;
	}

	public String getNickName()
	{
		return nickName;
	}

	/**
	 * Parses the address list from a Vector into a String.
	 */
	public static String parseAddressList(Vector addressList)
	{
		String addresses = new String();
		boolean firstAddress = true;

		for (Enumeration e = addressList.elements(); e.hasMoreElements();)
		{
			if (firstAddress)
			{
				addresses = (String) e.nextElement();
				firstAddress = false;
			}
			else
			{
				addresses = addresses + ", " + e.nextElement();
			}
		}

		return addresses;
	}

	/**
	 * Creates an Address object from the string
	 */
	public static EmailAddress parseRecipient(String recipient)
	{
		// Code from 1.4 parsing of Addresses should be put here to check for
		// brackets, pull out all neccessary info inaccordance with RFC 822.
		// For the moment it just creates and returns an Address object which 
		// has its email value set.
		EmailAddress address = new EmailAddress();
		int leftBracketIndex = recipient.indexOf((int) '<');

		// Address is not in "<x@y.z>" format
		if (leftBracketIndex == -1)
		{
			address.setEmailAddress(recipient);
		}
		else
		{
			String strAddress =
				recipient.substring(
					leftBracketIndex + 1,
					recipient.lastIndexOf((int) '>'));
			address.setEmailAddress(strAddress);

			// if string begins with "<" there is no nickname
			if (leftBracketIndex != 0)
			{
				String strNickname = recipient.substring(0, leftBracketIndex);
				address.setNickName(strNickname.trim());
			}
		}

		return address;
	}

	public void setEmailAddress(String emailAddress)
	{
		this.emailAddress = emailAddress;
	}

	public void setNickName(String nickName)
	{
		this.nickName = nickName;
	}

	/**
	 * Full string representation of the rfc822 address.
	 *
	 * Creation date: (20/02/2001 16:34:19)
	 * @author Magnus Hessel
	 * @return java.lang.String
	 */
	public String toString()
	{
		// TODO: When parsing has been implemented properly so that nickname is 
		// parsed out;
		// uncomment this code.
		//
		if (nickName != null)
		{
			return nickName + "<" + emailAddress + ">";
		}
		else
		{
			return emailAddress;
		}

		//return emailAddress;
	}
}
