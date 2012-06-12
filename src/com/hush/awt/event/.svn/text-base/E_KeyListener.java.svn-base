/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.awt.event;

import java.awt.event.KeyEvent;
import java.security.SecureRandom;

/**
 * Collects entropy from key strokes.
 * Creation date: (06/03/2001 21:51:15)
 */
public class E_KeyListener
	extends EntropyCollectionListener
	implements java.awt.event.KeyListener
{

	public E_KeyListener(
		SecureRandom random,
		int buffer,
		EntropyCollectionCallback callback)
	{
		super(random, buffer, callback);
	}

	public void collectKeyEvent(KeyEvent e)
	{
		collect(System.currentTimeMillis());
		collect(e.getKeyCode());
		collect(String.valueOf(e.getKeyChar()));
	}

	/**
	 * Invoked when a key has been pressed.
	 */
	public void keyPressed(java.awt.event.KeyEvent e)
	{
		collectKeyEvent(e);
	}

	/**
	 * Invoked when a key has been released.
	 */
	public void keyReleased(java.awt.event.KeyEvent e)
	{
		collectKeyEvent(e);
	}

	/**
	 * Invoked when a key has been typed.
	 * This event occurs when a key press is followed by a key release.
	 */
	public void keyTyped(java.awt.event.KeyEvent e)
	{
		collectKeyEvent(e);
	}
}