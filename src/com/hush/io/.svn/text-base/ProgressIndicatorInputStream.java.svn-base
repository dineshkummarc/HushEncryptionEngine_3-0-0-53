/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.io;


import java.io.IOException;
import java.io.InputStream;


public class ProgressIndicatorInputStream extends ContentLengthInputStream
{
	ProgressIndicator indicator = null;
	int total;
	int lastIncrement;

	public ProgressIndicatorInputStream(InputStream _in, int _available, 
										ProgressIndicator indicator)
	{
		super(_in, _available);
		this.total = _available;

		if (indicator != null)
		{
			indicator.setAmount(0, total);
		}

		this.lastIncrement = available;
		this.indicator = indicator;
	}

	public int read() throws IOException
	{
		int amount = super.read();

		if ((indicator != null) && ((lastIncrement - available) >= 2048))
		{
			indicator.setAmount(total - available, total);
			lastIncrement = available;
		}

		return amount;
	}

	public int read(byte[] b, int off, int len) throws IOException
	{
		int amount = super.read(b, off, len);

		if ((indicator != null) && ((lastIncrement - available) >= 2048))
		{
			indicator.setAmount(total - available, total);
			lastIncrement = available;
		}

		return amount;
	}

	public int read(byte[] b) throws IOException
	{
		int amount = super.read(b);

		if ((indicator != null) && ((lastIncrement - available) >= 2048))
		{
			indicator.setAmount(total - available, total);
			lastIncrement = available;
		}

		return amount;
	}
}