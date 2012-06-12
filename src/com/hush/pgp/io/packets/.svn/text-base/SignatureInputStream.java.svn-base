/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.IOException;
import java.io.InputStream;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.MPI;
import com.hush.pgp.Signature;
import com.hush.pgp.SignatureSubpacket;
import com.hush.util.Conversions;
import com.hush.util.Logger;

/**
 * A stream to read in a PGP signature.
 * <br>
 * The getters should be used to retrieve all information from this stream.
 * The standard <code>read</code> methods will just return EOF.
 *
 * @author Brian Smith
 *
 */
public class SignatureInputStream extends PacketContentInputStream
{
	private Signature signature;
	private boolean isRSA;

	/**
	 * Creates a <code>SignatureInputStream</code> and saves the arguments,
	 * the arguments for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * 
	 * @param in the underlying input stream
	 */
	public SignatureInputStream(InputStream in)
	{
		this(in, null, PACKET_TAG_SIGNATURE);
	}

	/**
	 * Creates a <code>SignatureInputStream</code> and saves the arguments,
	 * the arguments for later use.  In most cases
	 * <code>in</code> should be a <code>PacketInputStream</code>.
	 * <br>
	 * This constructor is intended to complete a signature that has
	 * already been started by a one pass signature packet.
	 * 
	 * @param in the underlying input stream
	 */
	public SignatureInputStream(InputStream in, Signature signature)
	{
		this(in, signature, PACKET_TAG_SIGNATURE);
	}

	protected SignatureInputStream(
		InputStream in,
		Signature signature,
		int packetTag)
	{
		super(in, packetTag);
		if (signature != null)
			this.signature = signature;
		else
			this.signature = new Signature();
	}

	/**
	 * Returns the <code>Signature</code> object retrieved from the
	 * PGP data.
	 * 
	 * @return the signature.
	 * @throws DataFormatException if there is a problem with the PGP data
	 * @throws IOException if an exception is thrown from the underyling stream
	 */
	public Signature getSignature() throws DataFormatException, IOException
	{
		init();
		return signature;
	}

	protected void engineInit() throws DataFormatException, IOException
	{
		// Read in the version.
		signature.setVersion(read());

		Logger.log(this, Logger.DEBUG, "Version: " + signature.getVersion());

		switch (signature.getVersion())
		{
			case -1 :
				throw new DataFormatException("Unexpected EOF while reading version number");
			case 2 :
			case 3 :
				initVersion3();
				break;
			case 4 :
				initVersion4();
				break;
			default :
				throw new DataFormatException(
					"Invalid version specifier: " + signature.getVersion());
		}
		finalInit();
	}

	private void initSignatureType() throws DataFormatException, IOException
	{
		int myByte;
		if ((myByte = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading signature type");
		signature.setSignatureType(myByte);
		Logger.log(this, Logger.DEBUG, "Signature type: " + myByte);
	}

	private void initPublicKeyAndHashAlgorithms()
		throws DataFormatException, IOException
	{
		int myByte;
		if ((myByte = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading public key algorithm");
		if ( myByte == CIPHER_RSA
		|| myByte == CIPHER_RSA_SIGN_ONLY
		|| myByte == CIPHER_RSA_ENCRYPT_ONLY )
		{
			isRSA = true;
		}
		else if ( myByte != CIPHER_DSA )
		{
			throw new DataFormatException("Unsupported signature type: " + myByte);
		}
		signature.setPublicKeyAlgorithm(myByte);
		Logger.log(this, Logger.DEBUG, "Public key algorithm: " + myByte);
		if ((myByte = read()) == -1)
			throw new DataFormatException("Unexpected EOF while reading hash algorithm");
		signature.setHashAlgorithm(myByte);
		Logger.log(this, Logger.DEBUG, "Hash algorithm: " + myByte);
	}

	private void initVersion3() throws DataFormatException, IOException
	{
		if (read() != 5)
			throw new DataFormatException("Expected length specifier of 5");
		initSignatureType();
		byte[] creationTimeBytes = new byte[4];
		if (read(creationTimeBytes) != 4)
			throw new DataFormatException("Unexpected EOF while reading creation time");
		signature.setCreationTime(
			Conversions.bytesToLong(creationTimeBytes),
			true,
			true);
		Logger.log(
			this,
			Logger.DEBUG,
			"Creation time: " + signature.getCreationTime(true));
		byte[] signerKeyID = new byte[8];
		if (read(signerKeyID) != 8)
			throw new DataFormatException("Unexpected EOF while reading signer key ID");
		Logger.hexlog(this, Logger.DEBUG, "Signer key ID: ", signerKeyID);
		signature.setIssuerKeyID(signerKeyID, true, true);
		initPublicKeyAndHashAlgorithms();

	}

	private void initVersion4() throws DataFormatException, IOException
	{
		initSignatureType();
		initPublicKeyAndHashAlgorithms();
		byte[] twoBytes = new byte[2];
		if (read(twoBytes) != 2)
			throw new DataFormatException("Unexpected EOF while reading hashed subpacket octet count");
		int hashedSubpacketOctetCount =
			(Conversions.unsignedByteToInt(twoBytes[0]) << 8)
				+ Conversions.unsignedByteToInt(twoBytes[1]);
		Logger.log(
			this,
			Logger.DEBUG,
			"Hashed subpacket octet count: " + hashedSubpacketOctetCount);
		while (hashedSubpacketOctetCount > 0)
		{
			SignatureSubpacket subpacket = new SignatureSubpacket(this);
			signature.addSubpacket(subpacket, true);
			hashedSubpacketOctetCount -= subpacket.getSubpacketSize();
		}
		if (read(twoBytes) != 2)
			throw new DataFormatException("Unexpected EOF while reading unhashed subpacket octet count");
		int unhashedSubpacketOctetCount =
			(Conversions.unsignedByteToInt(twoBytes[0]) << 8)
				+ Conversions.unsignedByteToInt(twoBytes[1]);
		Logger.log(
			this,
			Logger.DEBUG,
			"Unhashed subpacket octet count: " + unhashedSubpacketOctetCount);
		while (unhashedSubpacketOctetCount > 0)
		{
			SignatureSubpacket subpacket = new SignatureSubpacket(this);
			signature.addSubpacket(subpacket, false);
			unhashedSubpacketOctetCount -= subpacket.getSubpacketSize();
		}
	}

	private void finalInit() throws DataFormatException, IOException
	{
		byte[] leftSixteenBitsOfHash = new byte[2];
		if (read(leftSixteenBitsOfHash) != leftSixteenBitsOfHash.length)
			throw new DataFormatException("Unexpected EOF while reading leftmost sixteen bits of hash");
		signature.setLeftSixteenBitsOfHash(leftSixteenBitsOfHash);
		MPI[] signatureMPIs;
		if (isRSA) signatureMPIs = new MPI[1];
		else signatureMPIs = new MPI[2];
		
		signatureMPIs[0] = new MPI(this);
		if (!isRSA)
			signatureMPIs[1] = new MPI(this);
		signature.setSignatureMPIs(signatureMPIs);
	}
}