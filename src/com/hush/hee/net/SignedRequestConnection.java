/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.hush.pgp.Key;

public class SignedRequestConnection extends RequestConnection
{
	String alias;
	Key privateKey;
	SecureRandom random;

	public SignedRequestConnection(
		String server,
		Request request,
		String alias,
		Key privateKey,
		SecureRandom random)
	{
		super(server, request);
		this.alias = alias;
		this.privateKey = privateKey;
		this.random = random;
	}

	public OutputStream getOutputStream() throws IOException
	{

		SignedRequestOutputStream outputStream =
			new SignedRequestOutputStream(
				httpRequest.getOutputStream(),
				alias,
				privateKey,
				random);
		return outputStream;

	}
}