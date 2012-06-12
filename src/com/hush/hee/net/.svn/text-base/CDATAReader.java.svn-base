/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import java.io.IOException;

import com.hush.hee.KeyStoreException;

public class CDATAReader
{
	public static final String CDATA_END = "]]>";
	public static final String CDATA_START = "<![CDATA[";

	public static String process(RequestConnection connection)
		throws IOException, KeyStoreException
	{
		// String buffer to hold the cdata contents.
		StringBuffer strBuff = new StringBuffer(8192);

		char[] start = new char[CDATA_START.length()];
		connection.read(start);

		String startStr = new String(start);

		if (!startStr.equals(CDATA_START))
		{
			strBuff.append(startStr);
			connection.mark(2);
			int c1 = connection.read();
			while ( c1 != '<' )
			{
				strBuff.append((char)c1);
				connection.mark(2);
				c1 = connection.read();
			}
			connection.reset();
			return strBuff.toString();
		}

		boolean cdataEnd = false;

		while (!cdataEnd)
		{
			char c = (char) connection.read();

			if (c == ']')
			{
				char c1 = (char) connection.read();

				if (c1 == ']')
				{
					char c2 = (char) connection.read();

					if (c2 == '>')
					{
						cdataEnd = true;

						// Read through any white space after the CDATA
						char ws = ' ';

						while ((ws == '\r')
							|| (ws == '\n')
							|| (ws == ' ')
							|| (ws == '\t'))
						{
							connection.mark(3);
							ws = (char) connection.read();
						}

						connection.reset();
					}
					else
					{
						strBuff.append(c);
						strBuff.append(c1);
						strBuff.append(c2);
					}
				}
				else
				{
					strBuff.append(c);
					strBuff.append(c1);
				}
			}
			else
			{
				strBuff.append(c);
			}
		}
		return strBuff.toString();
	}

	public CDATAReader()
	{
		super();
	}
}