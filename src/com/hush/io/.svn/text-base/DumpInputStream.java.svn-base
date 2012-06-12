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
import java.io.OutputStream;

/**
 * This classes allows can wrap an InputStream and dump whatever is read from that
 * InputStream to a specified OutputStream.  Primarily used for debugging.
 */
public class DumpInputStream extends InputStream
{
	private OutputStream dump = null;

	private InputStream in = null;

	private boolean dumping = true;

	public DumpInputStream(InputStream in, OutputStream dump)
	{
		this.in = in;
		this.dump = dump;
	}

	public void setDumpstream(OutputStream dump)
	{
		this.dump = dump;
	}

	public int read() throws IOException
	{
		int b = in.read();
		if (dumping && b >= 0)
			dump.write(b);
		return b;
	}

	public int read(byte[] b) throws IOException
	{
		int amount = in.read(b);
		if (dumping && amount > 0)
			dump.write(b, 0, amount);
		return amount;
	}

	public int read(byte[] b, int offset, int len) throws IOException
	{
		int amount = in.read(b, offset, len);
		if (dumping && amount > 0)
			dump.write(b, offset, amount);
		return amount;
	}

	public void close() throws IOException
	{
		in.close();
	}

	public void mark(int mark)
	{
		in.mark(mark);
	}

	public boolean markSupported()
	{
		return in.markSupported();
	}

	public int available() throws IOException
	{
		return in.available();
	}

	public long skip(long l) throws IOException
	{
		return in.skip(l);
	}

	public void reset() throws IOException
	{
		in.reset();
	}

	public void setDumping(boolean dumping)
	{
		this.dumping = dumping;
	}
}
