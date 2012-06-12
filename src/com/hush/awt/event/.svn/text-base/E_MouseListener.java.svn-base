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
 * Collects entropy from mouse licks, enters, and exits.
 * Creation date: (06/03/2001 21:13:14)
 */
public class E_MouseListener
	extends EntropyCollectionListener
	implements java.awt.event.MouseListener
{

	public E_MouseListener(
		SecureRandom random,
		int buffer,
		EntropyCollectionCallback callback)
	{
		super(random, buffer, callback);
	}

	/**
	 * Invoked when the mouse has been clicked on a component.
	 */
	public void mouseClicked(java.awt.event.MouseEvent e)
	{
		super.collectMouseEvent(e);
	}

	/**
	 * Invoked when the mouse enters a component.
	 */
	public void mouseEntered(java.awt.event.MouseEvent e)
	{
		super.collectMouseEvent(e);
	}

	/**
	 * Invoked when the mouse exits a component.
	 */
	public void mouseExited(java.awt.event.MouseEvent e)
	{
		super.collectMouseEvent(e);
	}

	/**
	 * Invoked when a mouse button has been pressed on a component.
	 */
	public void mousePressed(java.awt.event.MouseEvent e)
	{
		super.collectMouseEvent(e);
	}

	/**
	 * Invoked when a mouse button has been released on a component.
	 */
	public void mouseReleased(java.awt.event.MouseEvent e)
	{
		super.collectMouseEvent(e);
	}
}