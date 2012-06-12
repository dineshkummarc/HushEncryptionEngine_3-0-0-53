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
 * Insert the type's description here.
 * Creation date: (06/03/2001 21:47:00)
 */
public class E_ActionListener
	extends EntropyCollectionListener
	implements java.awt.event.ActionListener
{

	public E_ActionListener(
		SecureRandom random,
		int buffer,
		EntropyCollectionCallback callback)
	{
		super(random, buffer, callback);
	}

	/**
	 * Invoked when an action occurs.
	 */
	public void actionPerformed(java.awt.event.ActionEvent e)
	{
		collect(e.getActionCommand());
		collect(e.getModifiers());
		collect(e.paramString());
	}
}