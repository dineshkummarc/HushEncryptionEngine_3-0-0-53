/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.applet.security;

import java.util.StringTokenizer;

/**
 * An interface to abstract and encapsulate the differing security environments provided
 * by Microsoft, Netscape, and Sun; however, this framework is extensible to allow any
 * other future security environment to be added.<p>
 *
 * In this framework, a platform-specific implementation of the Strategy interface is
 * used to execute code after securing or enabling permissions from the client security
 * platform.  Due to the problems of permission scoping/de-scoping, the code must be
 * (in some cases) executed within the same scope as the where the permissions are
 * granted by the security environment.  For this reason, code that is to be executed
 * is encapsulated with an implementation of the Badge interface; the specific permissions
 * required by the code to be executed determine which subclass of Badge the client
 * code should implement.  The subclasses of Badge are used as tags, allowing the compiler
 * to bind the call to <code>handle</code> to a Badge subclass-specific version of the
 * handle method, which allows specific permissions to be enabled on the client.<p>
 *
 * The disadvantage of this method is that new permissions capabilities are difficult to
 * add; each time something new is protected the security sandbox, a Badge for that
 * specific privilege must be created, and a <code>handle</code> method for that Badge
 * subclass must be added to the Strategy class, and all its concrete subclasses.  In
 * addition, supersets that exist in one security platform must have a <code>handle</code>
 * method in all the Strategy subclasses, even if the implementation is empty in all
 * but one case.<p>
 *
 * To endow a piece of code with a specific set of privileges, you create a Strategy
 * instance using the createStrategy method, and pass an object implementing a subclass of
 * the Badge interface to the <code>handle</code> method.  To prevent the creation of
 * a new class definition for every piece of code you need to be trusted, you can simply
 * use an anonymous inner class:<p>
 *
 *     <pre>
 *     Strategy strategy = Strategy.createStrategy();
 *     strategy.handle(new Badge() {
 *         public void invoke(Strategy strategy)
 *         {
 *             // Getting the home property requires property reading privileges.
 *             String h = System.getProperty("user.home");
 *             File hf = new File(h);
 *             final File ff = new File(hf, f);
 *
 *             // Checking the file existence requires file reading privileges.
 *             if (ff.exists())
 *                 System.err.println("File exists");
 *             else
 *                 System.err.println("File does not exist");
 *         });
 *     </pre><p>
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
abstract public class Strategy
{
	public String serverAddress;
	public String serverPort;

	/**
	 * Handles the given Badge object, enabling access to system properties.  Once the permission
	 * has been obtained from the client, the Badge's <code>invoke<code> method is
	 * called, allowing the Badge to execute priviledged code.<p>
	 *
	 * @param   b the Badge object to be handled once permission has been enabled.
	 */
	abstract public void handle(Badge b);

	/**
	 * Creates a Strategy implementation which is capable of enabling and disabling
	 * privileges within the client's security environment.  The choice of Strategy
	 * is based on the system 'java.vendor' property, which is different for each of
	 * the browsers.
	 *
	 * @return  a Strategy subclass for the client security environment or null.
	 */
	public static Strategy createStrategy()
	{
		try
		{
			String vendor =
				new StringTokenizer(System.getProperty("java.vendor"))
					.nextToken();
			String strategyClassName =
				"com.hush.applet.security." + vendor + "Strategy";
			Class c = Class.forName(strategyClassName);
			return (Strategy) c.newInstance();
		}
		catch (Throwable t)
		{
			// Default to SunStrategy if no others available.
			try
			{
				return (Strategy) Class
					.forName("com.hush.applet.security.SunStrategy")
					.newInstance();
			}
			catch (Throwable t2)
			{
				t2.printStackTrace();
				System.err.println(
					"Failed to create any security strategy, using empty strategy");
				return new EmptyStrategy();
			}
		}
	}

}