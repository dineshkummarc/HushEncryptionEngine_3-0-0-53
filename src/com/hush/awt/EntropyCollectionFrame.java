/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.awt;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Label;
import java.awt.Panel;
import java.security.SecureRandom;

import com.hush.awt.event.EntropyCollectionCallback;

/**
 * Insert the type's description here.
 * Creation date: (07/03/2001 16:11:03)
 */
public class EntropyCollectionFrame
	extends Frame
	implements EntropyCollectionCallback
{
	int bytesToCollect;
	ProgressBarPanel progressBarPanel;
	EntropyCollectionPanel entropyCollectionPanel;
	boolean initialized = false;
	Panel p;
	boolean finished = false;
	EntropyCollectionCallback callback = null;
	int storedValue = 0;

	public EntropyCollectionFrame(
		SecureRandom secureRandom,
		int bytesToCollect,
		String[] labels,
		EntropyCollectionCallback callback)
	{
		this.callback = callback;
		this.bytesToCollect = bytesToCollect;

		p = new Panel();

		GridBagLayout layout = new GridBagLayout();
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.CENTER;
		c.gridy = 0;
		c.gridx = 0;

		p.setLayout(layout);

		for (int n = 0; n < labels.length; n++)
		{
			Label l = new Label(labels[n]);
			l.paintAll(l.getGraphics());
			layout.setConstraints(l, c);
			p.add(l);
			c.gridy++;
		}

		entropyCollectionPanel =
			new EntropyCollectionPanel(secureRandom, 1024, this);
		entropyCollectionPanel.setBackground(this.getBackground());
		entropyCollectionPanel.setSize(new Dimension(500, 500));
		layout.setConstraints(entropyCollectionPanel, c);
		entropyCollectionPanel.paintAll(entropyCollectionPanel.getGraphics());
		p.add(entropyCollectionPanel);

		c.gridy++;

		progressBarPanel = new ProgressBarPanel(bytesToCollect / 1000);

		layout.setConstraints(progressBarPanel, c);

		progressBarPanel.paintAll(progressBarPanel.getGraphics());

		p.add(progressBarPanel);

		add(p, "Center");
	}

	public void setSize(Dimension d)
	{
		super.setSize(d);
		p.setSize(d);
		paintAll(getGraphics());
	}

	public void doCallback()
	{
		if (finished)
		{
			return;
		}

		int bytesCollected = entropyCollectionPanel.bytesCollected();

		if (bytesCollected >= bytesToCollect)
		{
			finished = true;
			callback.doCallback();

			return;
		}

		int newValue = bytesCollected / 1000;

		if (newValue != storedValue)
		{
			progressBarPanel.setActiveSegments(newValue);
			progressBarPanel.update(progressBarPanel.getGraphics());
			storedValue = newValue;
		}
	}

	public static void main(String[] args) throws Exception
	{
		/** A sample implementation
		
				
		hushclone.java.security.Security.addProvider(new com.hush.core.security.crypto.provider.HUSHCRYPTO());
		com.hush.core.security.crypto.provider.random.SHA1BlumBlumShubRandom rand = 
		new com.hush.core.security.crypto.provider.random.SHA1BlumBlumShubRandom();
				
		EntropyCollectionFrame frame = new EntropyCollectionFrame(rand,48000,new Label[]{ new Label("Please move your mouse around"), new Label("to generate your keys") });
		frame.setInactiveColor(Color.pink);
		frame.setActiveColor(Color.green);
		frame.setSize(new Dimension(400,500));
		frame.paintAll(frame.getGraphics());
		frame.setVisible(true);
		frame.doCollection();
		frame.setVisible(false);
		
		**/
	}

	public void setActiveColor(Color activeColor)
	{
		progressBarPanel.setActiveColor(activeColor);
	}

	public void setBackground(Color backgroundColor)
	{
		if (progressBarPanel != null)
		{
			progressBarPanel.setBackground(backgroundColor);
		}

		if (p != null)
		{
			p.setBackground(backgroundColor);
		}

		super.setBackground(backgroundColor);
	}

	public void setInactiveColor(Color inactiveColor)
	{
		progressBarPanel.setInactiveColor(inactiveColor);
		entropyCollectionPanel.setBackground(inactiveColor);
	}
}