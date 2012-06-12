/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

/**
 * Strips the relavent data from the input and stores it in the fields below
 *
 * @author      Declan Gallagher
 * @date        16th February, 2001
 * @version     Beta Version 2.0
 * @copyright   Copyright (c) 2001 by Hush Communications Corporation. 
 *
 * Example:
 * <emailProtocolResponse emailSession="12345" emailProtocol="imap" status="denied">
 *
 * name   = emailProtocolResponse
 * htAttr = emailSession   12345
 *          emailprotocol  imap
 *          status         denied
 *
 */
import java.util.Hashtable;
import java.util.StringTokenizer;


public class Tokeniser
{
	public String name;
	public Hashtable htAttr;
	public StringTokenizer strToken;
	public boolean singleTag = false;

	public Tokeniser(String str)
	{
		super();

		String key;
		String value;
		String input;
		StringTokenizer inToken;

		input = str.substring(1, str.length() - 1);

		int length = input.length();

		// If tag is a single tag remove single symbol / from end
		if ("/".equals(input.substring(length - 1, length)))
		{
			singleTag = true;
			input = input.substring(0, length - 1);
		}

		htAttr = new Hashtable();
		strToken = new StringTokenizer(input);

		name = strToken.nextToken();

		while (strToken.hasMoreTokens())
		{
			inToken = new StringTokenizer(strToken.nextToken("\""));

			key = inToken.nextToken("=");

			if (" ".equals(key.substring(0, 1)))
			{
				key = key.substring(1, key.length());
			}

			inToken = new StringTokenizer(strToken.nextToken("\""));

			value = inToken.nextToken("\"");

			htAttr.put(key, value);
		}
	}
}