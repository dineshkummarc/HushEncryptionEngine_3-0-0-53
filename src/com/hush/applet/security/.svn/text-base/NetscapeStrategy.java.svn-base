/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.applet.security;

import netscape.security.PrivilegeManager;

/**
 * An implementation of the Strategy interface which enables code to be trusted in the
 * Netscape JVM environment of Netscape Navigator.<p>
 *
 * The NetscapeStrategy uses the Netscape-specific security framework to enable a
 * signed class to obtain permissions from the user/client in order to perform Java
 * operations outside of the security sandbox, such as reading or writing to the
 * client machine's hard-drive.<p>
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
public class NetscapeStrategy extends Strategy
{
	public NetscapeStrategy()
	{
	}

	/**
	 * Handles the given Badge object, enabling all privileges.  Once the permission
	 * has been obtained from the client, the Badge's <code>invoke<code> method is
	 * called, allowing the Badge to execute priviledged code.<p>
	 *
	 * @param   b the Badge object to be handled once permission has been enabled.
	 */
	public void handle(Badge b)
	{
		PrivilegeManager.enablePrivilege("UniversalFileRead");
		PrivilegeManager.enablePrivilege("UniversalFileWrite");
		PrivilegeManager.enablePrivilege("UniversalFileDelete");
		PrivilegeManager.enablePrivilege("TerminalEmulator");
		PrivilegeManager.enablePrivilege("UniversalPropertyRead");
		PrivilegeManager.enablePrivilege("UniversalPropertyWrite");
		PrivilegeManager.enablePrivilege("UniversalSystemClipboardAccess");
		PrivilegeManager.enablePrivilege("UniversalThreadAccess");
		b.invoke(this);
	}
}