/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.hee.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.hush.pgp.Key;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;
import com.hush.util.UnrecoverableKeyException;

public class SignedRequestOutputStream extends OutputStream
{
	OutputStream myUnderlyingOutputStream;
	ByteArrayOutputStream buffer;
	Key privateKey;
	String alias;
	SecureRandom random;

	public SignedRequestOutputStream(
		OutputStream underlyingOutputStream,
		String alias,
		Key privateKey,
		SecureRandom random)
	{
		super();
		buffer = new ByteArrayOutputStream();
		myUnderlyingOutputStream = underlyingOutputStream;
		this.random = random;
		this.alias = alias;
		this.privateKey = privateKey;
	}

	public void write(int value) throws IOException
	{
		buffer.write(value);
	}

	public void flush()
	{
	}

	public void close() throws IOException
	{

		byte[] data;

		data = buffer.toByteArray();
		buffer.reset();

		if (data.length < 1)
			// Guard for flushing a zero length buffer. May occur at close().
		{
			return;
		}

		ByteArrayOutputStream signedData = new ByteArrayOutputStream();
		/*
		PgpMessageOutputStream pgpOutputStream =
			new PgpMessageOutputStream(
				signedData,
				0,
				random,
				false,
				null,
				System.currentTimeMillis() / 1000,
				-1,
				false,
				Deflater.BEST_COMPRESSION,
				true,
				false);
		*/
		PgpMessageOutputStream pgpOutputStream =
			new PgpMessageOutputStream(signedData, random);
		pgpOutputStream.setUseArmor(true);
		pgpOutputStream.addOnePassSigner(privateKey);
		pgpOutputStream.setPlaintext(true);
		pgpOutputStream.write(data);
		pgpOutputStream.close();
		byte[] signedMessage = signedData.toByteArray();
		// add xml header
		writeStringToUnderlying(RequestConnection.XML_HEADER);
		writeStringToUnderlying("\r\n");
		// add request header
		writeStringToUnderlying(
			RequestConnection.REQUEST_BLOCK_START);
		writeStringToUnderlying("\r\n");
		writeStringToUnderlying("<signedRequest>\r\n");
		writeStringToUnderlying("<signer alias=\"");
		writeStringToUnderlying(alias);
		writeStringToUnderlying("\"/>\r\n");
		writeStringToUnderlying("<signedRequestPacket>\r\n");
		writeStringToUnderlying("<![CDATA[");
		myUnderlyingOutputStream.write(signedMessage);
		writeStringToUnderlying("]]>\r\n");
		writeStringToUnderlying("</signedRequestPacket>\r\n");
		writeStringToUnderlying("</signedRequest>\r\n");
		writeStringToUnderlying(
			RequestConnection.REQUEST_BLOCK_START_END);
		myUnderlyingOutputStream.flush();
		myUnderlyingOutputStream.close();
	}
	
	private void writeStringToUnderlying(String s) throws IOException
	{
		myUnderlyingOutputStream.write(Conversions.stringToByteArray(s,
				PgpConstants.UTF8));
	}
}
