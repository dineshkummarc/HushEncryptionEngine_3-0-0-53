/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

/**
 * An abstraction of a request to the HushMail server to perform a function.
 *
 * Add explanation of response codes.
 *
 * @author      Brendon J. Wilson
 * @date        October 8th, 1999
 * @version     Beta Version 1.2
 * @copyright   Copyright (c) 1999, 2000 by Hush Communications Corporation, BWI.
 */

import java.io.IOException;
import java.util.Hashtable;

import com.hush.hee.BadRequestException;
import com.hush.hee.DeniedException;
import com.hush.hee.KeyStoreException;
import com.hush.hee.NotFoundException;

public abstract class Request implements RequestConstants
{
	/**
	 * The connection to the server.
	 */
	protected RequestConnection connection;

	protected Hashtable attributes;

	protected String lastLine = null;
	
	public abstract String getType();

	/**
	 * Processes the response to the request from the server, reading from
	 * the XML tag that starts the request to the XML taga that finishes it
	 * extracting all returned data into variables that can be accessed through
	 * methods on the individual subclasses of this abstract class.
	 *
	 * @exception   ProtocolException thrown when the protocol is violated.
	 */
	public void processResponse() throws IOException, KeyStoreException
	{
		String currentLine = connection.readLine();

		Tokeniser tk = new Tokeniser(currentLine);
		attributes = tk.htAttr;
		String status;
		if ((getType() + RESPONSE).equalsIgnoreCase(tk.name))
		{
			status = (String) tk.htAttr.get(STATUS);
		}
		else
			throw new KeyStoreException("Expecting: " + getType() + RESPONSE);
		
		if ( STATUS_DENIED.equals(status) ) throw new DeniedException();
		
		else if ( STATUS_NOT_FOUND.equals(status) )
		{
			handleNotFound();
			return;
		}
			
		else if ( STATUS_BAD_REQUEST.equals(status) ) throw new BadRequestException("Bad request to keyserver");
		
		else if ( STATUS_SERVER_ERROR.equals(status) ) throw new KeyStoreException("Unknown server error");
		
		else if (STATUS_SUCCESSFUL.equalsIgnoreCase(status))
			processBody();

		else throw new RuntimeException("Should not get here");
		
		if (!tk.singleTag)
		{
			if (lastLine != null)
				currentLine = lastLine;
			else
				currentLine = connection.readLine();

			tk = new Tokeniser(currentLine);
			if (!("/" + getType() + RESPONSE).equalsIgnoreCase(tk.name))
				throw new KeyStoreException(
					"Expecting: " + "/" + getType() + RESPONSE);
		}
	}

	public void processBody() throws IOException, KeyStoreException
	{
	}
	
	protected void handleNotFound() throws NotFoundException
	{
		throw new NotFoundException();
	}
	
	/**
	 * Sends the command request to the server, writing from the XML tag that
	 * starts the request to the XML tag that finishes it.  Concrete implementations of
	 * the Request class need to provide an implementation here, which sends
	 * the actual request to the server.
	 */
	public abstract void sendRequest();

	/**
	 * Sets the connection which the Request object will use to communicate
	 * with the server in order to request services.
	 *
	 * @param   requestConnection the request connection to the server.
	 */
	public void setConnection(RequestConnection requestConnection)
	{
		this.connection = requestConnection;
	}
}