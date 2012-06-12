/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.applet.security;

/**
 * A tagging interface, which identifies the type of privileges to be bestowed on
 * an class.  Subclasses of the Badge interface are used to tag a class for proper
 * handling by a subclass of the Strategy class.<p>
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
public interface Badge
{
	/**
	 * Invokes the piece of code requiring the privileges determined by the concrete 
	 * subclass of Badge implementing this method in conjunction with the concrete
	 * subclass of Strategy which endows the required privileges in a security-
	 * platform-specific manner.<p>
	 *
	 * The Strategy is passed to the invoke method even though it may not be required
	 * by the code to be trusted, as the Strategy may be required to endow additional
	 * privileges to other libraries of code.
	 *
	 * @param   manager the Strategy manner to handle requesting privileges.
	 */
	void invoke(Strategy manager);
}