/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

/*
 * This is an implementation of an InputStream that "remembers" a certain
 * number of bytes previously read from it.
 */

package com.hush.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CachingInputStream extends InputStream
{
	private InputStream in;
	private byte[] cache;
	private int cacheStart = 0;
	private int cacheSize = 0;

	public CachingInputStream(InputStream in, int cacheSize)
	{
		this.in = in;
		cache = new byte[cacheSize];
	}

	public int read() throws IOException
	{
		int retVal = in.read();
		if ( retVal == -1 ) return retVal;
		cache[cacheStart] = (byte) ( retVal < 128 ? retVal : retVal - 256 );
		if ( ++cacheStart >= cache.length ) cacheStart = 0;
		if ( cacheSize < cache.length ) cacheSize++;
		return retVal;
	}

	public int read(byte[] b) throws IOException
	{
		return read(b, 0, b.length);
	}

	public int read(byte[] b, int offset, int len) throws IOException
	{
		int bytesRead = in.read(b, offset, len);
		if ( bytesRead == -1 ) return bytesRead;

		if ( bytesRead >= cache.length )
		{
			System.arraycopy(b, offset + ( bytesRead - cache.length),
			cache, 0, cache.length);
			cacheStart = 0;
			cacheSize = cache.length;
			return bytesRead;
		}

		int bytesUntilEndOfCache = cache.length - cacheStart;
		int bytesToCopy = bytesRead < cache.length ? bytesRead : cache.length;
		int bytesToCopyFirst = 	bytesToCopy < bytesUntilEndOfCache ?
			bytesToCopy : bytesUntilEndOfCache;
		System.arraycopy(b, offset, cache, cacheStart, bytesToCopyFirst);
		if ( ( cacheStart += bytesToCopyFirst ) >= cache.length ) cacheStart = 0;
		int bytesToCopySecond = bytesToCopy - bytesToCopyFirst;
		if ( bytesToCopySecond != 0 )
		{
			System.arraycopy(b, offset + bytesToCopyFirst, cache, cacheStart,
				bytesToCopySecond);
			if ( ( cacheStart += bytesToCopySecond ) >= cache.length ) cacheStart = 0;
		}
		if ( cacheSize != cache.length )
		{
			cacheSize = cache.length < cacheSize + bytesToCopy ?
				cache.length : ( cacheSize + bytesToCopy );
		}
		return bytesRead;
	}

	public byte[] getCache()
	{
		byte[] retVal = new byte[cacheSize];
		int chunk1 = cacheSize - cacheStart;
		int chunk2 = cacheSize - chunk1;
		System.arraycopy(cache, cacheStart, retVal, 0, chunk1);
		if ( chunk2 > 0 )
			System.arraycopy(cache, 0, retVal, chunk1, chunk2);
		return retVal;
	}

	public static void main(String[] argv) throws IOException
	{
		CachingInputStream c = new CachingInputStream(
			new ByteArrayInputStream(new byte[]
			{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } ), 4);
		//System.out.println(c.read());
		//System.out.println(com.hush.util.Conversions.bytesToHexString(c.getCache()));
		//System.out.println(c.read());
		//System.out.println(com.hush.util.Conversions.bytesToHexString(c.getCache()));

		byte[] b = new byte[8];
		System.out.println(c.read(b));
		System.out.println(com.hush.util.Conversions.bytesToHexString(c.getCache()));

		//b = new byte[3];
		//System.out.println(c.read(b));
		//System.out.println(com.hush.util.Conversions.bytesToHexString(c.getCache()));
	}
}