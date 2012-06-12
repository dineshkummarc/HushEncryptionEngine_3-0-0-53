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
 * Collects entropy from mouse movements.
 * Creation date: (06/03/2001 21:23:58)
 */
public class E_MouseMotionListener extends EntropyCollectionListener
	implements java.awt.event.MouseMotionListener
{

	public E_MouseMotionListener(SecureRandom random, 
								 int buffer, EntropyCollectionCallback callback)
	{
		super(random, buffer, callback);
	}

	/**
	 * Invoked when a mouse button is pressed on a component and then 
	 * dragged.  Mouse drag events will continue to be delivered to
	 * the component where the first originated until the mouse button is
	 * released (regardless of whether the mouse position is within the
	 * bounds of the component).
	 */
	public void mouseDragged(java.awt.event.MouseEvent e)
	{
		collectMouseEvent(e);
	}

	/**
	 * Invoked when the mouse button has been moved on a component
	 * (with no buttons no down).
	 */
	public void mouseMoved(java.awt.event.MouseEvent e)
	{
		collectMouseEvent(e);
	}
}