/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.applet.security;

/**
 * An implementation of the Strategy interface which enables code to be trusted in the 
 * JVM environment of Empty's VisualAge for Java.<p>
 *
 * This class is meant primarily as a stub, to allow developers to test code within
 * VisualAge for Java, without having to deal with any of the configuration details
 * required to setup Java security policies within VAJ.  It allows the code to be
 * used 'as is' without commenting out sections of code relating to the security
 * Strategy framework.<p>
 *
 * This class, and the security framework it is a part of, are based on the article
 * by Greg Frascadore appearing in the May 1999 edition of Java-Pro magazine.  The
 * full article and a copy of the example source code provided by the article are
 * available from Java-Pro's web site at:<p>
 *
 *     http://www.devx.com/upload/free/features/javapro/1999/05may99/gf0599/gf0599.asp
 *
 * @author      Brendon J. Wilson
 * @date        April 26th, 2000
 * @version     Beta Version 1.3
 * @copyright   Copyright (c) 1999-2000 by Hush Communications Corporation, BWI.
 */
public class EmptyStrategy extends Strategy
{
	/**
	 * Creates a new object to deal with obtaining permissions from the Netscape-specific
	 * security environment.  Unlike the MicrosoftStrategy, there is a need for a permission 
	 * forecast by the constructor. The Netscape security environment will allow an applet 
	 * to begin execution even if the permissions required at a later execution point by the 
	 * applet are not approved by the client; an exception will be thrown at the time when
	 * un-privileged code is executes.  To prevent this from happening, a permission forecast
	 * is performed by the constructor to allow the exception to be caught up front.
	 */
	public EmptyStrategy()
	{
	}

	/**
	 * Handles the given Badge object, enabling access to the clipboard.  Once the permission 
	 * has been obtained from the client, the Badge's <code>invoke<code> method is 
	 * called, allowing the Badge to execute privileged code.<p>
	 *
	 * @param   b the Badge object to be handled once permission has been enabled.
	 */
	public void handle(Badge b)
	{
		// Invoke the Badge's action within the permission scope.
		b.invoke(this);
	}

	public void addServerDetails(String address)
	{
	}

}