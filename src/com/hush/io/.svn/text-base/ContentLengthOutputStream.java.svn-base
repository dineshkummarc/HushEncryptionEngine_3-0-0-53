/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.io;

import java.io.IOException;
import java.io.OutputStream;

public class ContentLengthOutputStream extends OutputStream
{
	private OutputStream out;
	private long contentLength = 0;

	public ContentLengthOutputStream(OutputStream out)
	{
		this.out = out;
	}

	public void close() throws IOException
	{
		out.close();
	}

	public void flush() throws IOException
	{
		out.flush();
	}

	public void write(byte[] b) throws IOException
	{
		out.write(b);
		contentLength += b.length;
	}
	public void write(byte[] b, int off, int len) throws IOException
	{
		out.write(b, off, len);
		contentLength += len;
	}

	public void write(int b) throws IOException
	{
		out.write(b);
		contentLength += 1;
	}

	public long getContentLength()
	{
		return contentLength;
	}

}
