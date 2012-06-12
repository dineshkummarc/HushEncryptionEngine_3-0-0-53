/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

/**
 * Request for the server to generate a private key nonce.
 * This nonce is then used with the private key comms protocol requests - PrivateKeyLookup 
 * & PrivateKeyUpdate. The nonce has a life span of 60 seconds after which time any
 * requests using it will not be accepted. This is part of the servers dictionary attack
 * security.
 *
 * @copyright   Copyright (c) 2001 by Hush Communications Corporation.
 */
import java.io.IOException;
import com.hush.hee.KeyStoreException;

public class RequestNonce extends Request
{
	private final String NONCE_RESPONSE = "RequestNonceResponse";
	private final String NONCE = "nonce";
	private String nonce = null;

	public String getType()
	{
		return "RequestNonce";
	}

	public String getNonce()
	{
		return nonce;
	}

	public void processBody() throws IOException, KeyStoreException
	{
		nonce = (String) attributes.get(NONCE);
	}

	/**
	 * Send the requestNonce request to the server.
	 */
	public void sendRequest()
	{
		connection.write("<requestNonce/>");
	}
}