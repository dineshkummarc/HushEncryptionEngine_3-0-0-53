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


public class ContentLengthInputStream extends InputStream
{
	protected int available = 0;
	InputStream in;

	public ContentLengthInputStream(InputStream _in, int _available)
	{
		in = _in;
		available = _available;
	}

	public int read() throws IOException
	{
		int retVal = in.read();
		available--;

		return retVal;
	}

	public int read(byte[] b, int off, int len) throws IOException
	{
		int read = in.read(b, off, len);
		available -= read;

		return read;
	}

	public int read(byte[] b) throws IOException
	{
		int read = in.read(b);
		available -= read;

		return read;
	}

	public int available()
	{
		return available;
	}

	public boolean markSupported()
	{
		return false;
	}

	public void mark()
	{
	}

	public void reset() throws IOException
	{
		throw new IOException();
	}

	public long skip(long n) throws IOException
	{
		int skipped = (int) in.skip(n);
		available -= skipped;

		return available;
	}

	public void close() throws IOException
	{
		in.close();
		super.close();
	}
}