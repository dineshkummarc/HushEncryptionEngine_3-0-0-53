/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.awt.event;

import com.hush.pgp.PgpConstants;
import com.hush.util.Conversions;

import java.security.SecureRandom;

import java.util.EventListener;

import java.awt.event.MouseEvent;

/**
 * This class provides a foundation for entropy collecting
 * event listeners for every purpose.
 *
 * Creation date: (06/03/2001 18:46:16)
 */
public class EntropyCollectionListener implements EventListener
{
	/**
	 * The random number generator that receives and distills the entropy.
	 */
	private SecureRandom secureRandom;

	/**
	 * The number of bytes to collect before reseeding secureRandom.
	 */
	private int maxBufferSize;

	/**
	 * A buffer to store bytes before using them to reseed secureRandom.
	 */
	private byte[] buffer;

	/**
	 * A count of the bytes in the buffer right now
	 */
	private int currentBufferSize = 0;
	private EntropyCollectionCallback callback = null;

	/**
	 * The total number of bytes that have been collected and seeded into
	 * secureRandom so far.
	 */
	private int bytesCollected = 0;

	protected EntropyCollectionListener()
	{
	}

	/**
	 * Sets the random object.  Initializes buffer.
	 */
	public EntropyCollectionListener(SecureRandom secureRandom)
	{
		this(secureRandom, 1024);
	}

	/**
	 * Sets the random object.  Initializes buffer.
	 */
	public EntropyCollectionListener(SecureRandom secureRandom, int bufferSize)
	{
		this.secureRandom = secureRandom;
		maxBufferSize = bufferSize;
		buffer = new byte[bufferSize];
	}

	/**
	 * Sets the random object.  Initializes buffer.
	 */
	public EntropyCollectionListener(
		SecureRandom secureRandom,
		int bufferSize,
		EntropyCollectionCallback callback)
	{
		this.secureRandom = secureRandom;
		this.callback = callback;
		maxBufferSize = bufferSize;
		buffer = new byte[bufferSize];
	}

	protected void collect(String str)
	{
		collect(Conversions.stringToByteArray(str, PgpConstants.UTF8));
	}
	
	/**
	 * Store bytes in a buffer.  If the buffer is full, reseed SecureRandom with
	 * the contents.
	 */
	protected void collect(byte[] bytes)
	{

		int bytesToUse =
			(bytes.length > (maxBufferSize - currentBufferSize))
				? (maxBufferSize - currentBufferSize)
				: bytes.length;
		System.arraycopy(bytes, 0, buffer, currentBufferSize, bytesToUse);
		currentBufferSize += bytesToUse;

		if (currentBufferSize == maxBufferSize)
		{
			secureRandom.setSeed(buffer);
			bytesCollected += buffer.length;
			currentBufferSize = 0;
		}

		if (callback != null)
		{
			callback.doCallback();
		}
	}

	/**
	 * Store bytes in a buffer.  If the buffer is full, reseed SecureRandom with
	 * the contents.
	 */
	protected void collect(int data)
	{
		collect(Conversions.intToBytes(data));
	}

	/**
	 * Store bytes in a buffer.  If the buffer is full, reseed SecureRandom with
	 * the contents.
	 */
	protected void collect(long data)
	{
		byte[] b = new byte[8];
		Conversions.longToBytes(data, b, 0, b.length);
		collect(b);
	}

	/**
	 * Store bytes in a buffer.  If the buffer is full, reseed SecureRandom with
	 * the contents.
	 */
	protected void collect(boolean data)
	{
		// Since we assume secureRandom has a good mixing function, it's okay
		// enqueue eight bits for a boolean value.
		collect(data ? (byte) 1 : (byte) 0);
	}

	/**
	 * Collects all the entropy associated with a mouse even.
	 */
	protected void collectMouseEvent(MouseEvent event)
	{
		collect(System.currentTimeMillis());

		//collect(event.getClickCount());
		collect(event.getX());
		collect(event.getY());

		//collect(event.isPopupTrigger());
	}

	/**
	 * Allows the SecureRandom object to be retrieved from the
	 * event handler.
	 * Creation date: (06/03/2001 19:36:54)
	 * @return hushclone.java.security.SecureRandom
	 */
	public SecureRandom getSecureRandom()
	{
		return secureRandom;
	}

	public int bytesCollected()
	{
		return bytesCollected;
	}
}
