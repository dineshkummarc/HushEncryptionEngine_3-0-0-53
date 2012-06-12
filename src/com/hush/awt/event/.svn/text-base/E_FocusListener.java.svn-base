/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.awt.event;

import java.security.SecureRandom;

/**
 * Collects entropy based on the timing of gain/loss of focus.
 * Creation date: (06/03/2001 22:08:53)
 */
public class E_FocusListener
	extends EntropyCollectionListener
	implements java.awt.event.FocusListener
{

	public E_FocusListener(
		SecureRandom random,
		int buffer,
		EntropyCollectionCallback callback)
	{
		super(random, buffer, callback);
	}

	/**
	 * Invoked when a component gains the keyboard focus.
	 */
	public void focusGained(java.awt.event.FocusEvent e)
	{
		collect(e.isTemporary());
		collect(System.currentTimeMillis());
	}

	/**
	 * Invoked when a component loses the keyboard focus.
	 */
	public void focusLost(java.awt.event.FocusEvent e)
	{
		collect(e.isTemporary());
		collect(System.currentTimeMillis());
	}
}