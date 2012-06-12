/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.awt;

import java.awt.Dimension;
import java.awt.Panel;
import java.security.SecureRandom;

import com.hush.awt.event.E_FocusListener;
import com.hush.awt.event.E_KeyListener;
import com.hush.awt.event.E_MouseListener;
import com.hush.awt.event.E_MouseMotionListener;
import com.hush.awt.event.EntropyCollectionCallback;


/**
 * A panel that traps all events associated with it and pumps them
 * into a SecureRandom instance.  Intended to entropy collection, primarily
 * a panel for collecting mouse movement.
 * Creation date: (06/03/2001 18:46:16)
 */
public class EntropyCollectionPanel extends Panel
{
	/**
	 * The random number generator that receives and distills the entropy.
	 */
	private SecureRandom secureRandom;
	private E_FocusListener focusListener;
	private E_KeyListener keyListener;
	private E_MouseListener mouseListener;
	private E_MouseMotionListener mouseMotionListener;

	public EntropyCollectionPanel(SecureRandom secureRandom)
	{
		super();
		initialize(secureRandom, 1024, null);
	}

	public EntropyCollectionPanel(SecureRandom secureRandom, int bufferSize, 
								  EntropyCollectionCallback callback)
	{
		super();
		initialize(secureRandom, bufferSize, callback);
	}

	public EntropyCollectionPanel(java.awt.LayoutManager layout, 
								  SecureRandom secureRandom)
	{
		super(layout);
		initialize(secureRandom, 1024, null);
	}

	public SecureRandom getSecureRandom()
	{
		return secureRandom;
	}

	/**
	 * Sets the random object, and initializes event listeners
	 */
	public void initialize(SecureRandom secureRandom, int bufferSize, 
						   EntropyCollectionCallback callback)
	{
		this.secureRandom = secureRandom;


		//mouseListener = new E_MouseListener(secureRandom,1024, callback);
		//addMouseListener(mouseListener);
		mouseMotionListener = new E_MouseMotionListener(secureRandom, 1024, 
														callback);
		addMouseMotionListener(mouseMotionListener);

		//focusListener = new E_FocusListener(secureRandom, 1024, callback);
		//addFocusListener(focusListener);
		//keyListener = new E_KeyListener(secureRandom,1024, callback);
		//addKeyListener(keyListener);
	}

	public int bytesCollected()
	{
		//return (mouseListener.bytesCollected() + mouseMotionListener.bytesCollected() +
		//	focusListener.bytesCollected() + keyListener.bytesCollected());
		return (mouseMotionListener.bytesCollected());
	}

	public Dimension minimumSize()
	{
		return new Dimension(256, 256);
	}

	public Dimension preferredSize()
	{
		return new Dimension(256, 256);
	}
}