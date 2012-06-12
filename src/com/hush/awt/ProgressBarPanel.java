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
import java.awt.Graphics;
import java.awt.Image;
import java.awt.Panel;


/**
 * A panel for displaying the progress of the user's entropy generation.<p>
 *
 * @author      Brendon Wilson
 * @date        November 30th, 1999
 * @version     Beta Version 1.2
 * @copyright   Copyright (c) 1999, 2000 by Hush Communications Corporation, BWI.
 */
public class ProgressBarPanel extends Panel
{
	/**
	 * The number of segments for the progress bar.
	 */
	private int numberOfSegments;

	/**
	 * The number of segments currently active.
	 */
	private int numberOfActiveSegments = 0;
	private Color activeColor = Color.red;
	private Color inactiveColor = Color.black;

	/**
	 * Create a progress bar with the given number of segments.
	 *
	 * @param   numberOfSements the number of segments for the progress bar.
	 */
	public ProgressBarPanel(int numberOfSegments)
	{
		super();
		this.numberOfSegments = numberOfSegments;
	}

	/**
	 * Returns the number of active segments in the progress bar.
	 *
	 * @return  the number of segments in the bar currently activated.
	 */
	public int getActiveSegments()
	{
		return numberOfActiveSegments;
	}

	/**
	 * Returns the number of active segments in the progress bar.
	 *
	 * @return  the number of segments in the progress bar.
	 */
	public int getNumberOfSegments()
	{
		return numberOfSegments;
	}

	/**
	 * Returns the minimum dimensions of the panel.
	 *
	 * @return  the minimum dimensions of the panel.
	 */
	public Dimension minimumSize()
	{
		return new Dimension(256, 40);
	}

	/**
	 * Paints the progress bar.  Uses double buffering to avoid flicker.
	 *
	 * @param   g the graphics context to use to draw the progress bar.
	 */
	public void paint(Graphics g)
	{
		// Use double buffering to eliminate flicker in repaint.
		Image imageBuffer = createImage(this.size().width, this.size().height);
		Graphics buffer = imageBuffer.getGraphics();


		// Fill the background for the progress bar.
		buffer.setColor(this.getBackground());
		buffer.fillRect(0, 0, this.size().width, this.size().height);

		// Calculate the width, height and spacing of the progress bar segments.
		int segmentWidth = (int) ((1 / (numberOfSegments + 
								   (0.75 * (numberOfSegments - 1)) + 2)) * (bounds().width));
		int segmentHeight = (int) (0.75 * bounds().height);
		int segmentSpace = (int) (0.75 * segmentWidth);
		int segmentMargin = (int) ((bounds().width - 
								(numberOfSegments * segmentWidth) - 
								(numberOfSegments - 1) * segmentSpace) / 2);


		// Draw the number of active segments.
		buffer.setColor(activeColor);

		for (int i = 1; i <= numberOfActiveSegments; i++)
		{
			int x = ((i - 1) * segmentSpace) + ((i - 1) * segmentWidth) + 
					segmentMargin;
			int y = (int) ((bounds().height - segmentHeight) / 2);
			buffer.fillRect(x, y, segmentWidth, segmentHeight);
		}


		// Draw the remaining inactive segments.
		buffer.setColor(inactiveColor);

		for (int i = numberOfActiveSegments + 1; i <= numberOfSegments; i++)
		{
			int x = ((i - 1) * segmentSpace) + ((i - 1) * segmentWidth) + 
					segmentMargin;
			int y = (int) ((bounds().height - segmentHeight) / 2);
			buffer.fillRect(x, y, segmentWidth, segmentHeight);
		}


		// Copy the buffer image to the screen.
		g.drawImage(imageBuffer, 0, 0, this);


		// Dispose of the graphics buffer.
		buffer.dispose();
	}

	/**
	 * Returns the preferred dimensions of the panel.
	 *
	 * @return  the preferred dimensions of the panel.
	 */
	public Dimension preferredSize()
	{
		return new Dimension(256, 40);
	}

	/**
	 * Sets the number of active segments in the progress bar.
	 *
	 * @param  activeSegments the number of segments in the bar to activate.
	 */
	public void setActiveSegments(int activeSegments)
	{
		this.numberOfActiveSegments = activeSegments;
	}

	/**
	 * Sets the number of segments in the progress bar.
	 *
	 * @param   numberOfSegments the number of segments in the progress bar.
	 */
	public void setNumberOfSegments(int numberOfSegments)
	{
		this.numberOfSegments = numberOfSegments;
	}

	/**
	 * Overrides <code>update</code> and calls <code>paint</code> directly.
	 *
	 * @param   g the Graphics context to use for painting.
	 */
	public void update(Graphics g)
	{
		paint(g);
	}

	public void setActiveColor(Color activeColor)
	{
		this.activeColor = activeColor;
	}

	public void setInactiveColor(Color inactiveColor)
	{
		this.inactiveColor = inactiveColor;
	}
}