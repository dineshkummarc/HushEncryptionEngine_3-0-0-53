/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.awt;

import java.awt.Frame;
import java.awt.Graphics;
import java.awt.Label;

import com.hush.io.ProgressIndicator;


public class GenericIndicator extends Frame implements ProgressIndicator
{
	Label l;
	String onFinished = null;
	long amount = 0;
	long total = 1;

	public GenericIndicator()
	{
		super();
		setResizable(false);
		l = new Label("");
		l.setBackground(new java.awt.Color(0x66, 0x66, 0x66));
		l.setForeground(new java.awt.Color(255, 255, 255));
		l.setAlignment(Label.CENTER);
	}

	public void setFinishedText(String text)
	{
		onFinished = text;
	}

	public void setAmount(long amount, long total)
	{
		this.amount = amount;
		this.total = total;
		invalidate();
		repaint();
	}

	public void paint(Graphics g)
	{
		double current = (double) amount / (double) total * getSize().width;
		int percent = (int) Math.ceil((double) amount / (double) total * 100);

		l.setSize((int) current, getSize().height);

		if ((percent == 100) && (onFinished != null))
		{
			l.setText(onFinished);
		}
		else
		{
			l.setText(percent + "%");
		}

		if (!isAncestorOf(l))
		{
			add(l);
		}
	}
}