/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp.io.packets;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.hush.pgp.AlgorithmFactory;
import com.hush.pgp.DataFormatException;
import com.hush.pgp.cfb.CFBParameters;
import com.hush.util.ArrayTools;

/**
 * A stream to write out PGP symmetrically encrypted data.
 *
 * @author Brian Smith
 */
public class SymmetricallyEncryptedDataOutputStream
	extends PacketContentOutputStream
{
	protected BufferedBlockCipher cipher;
	protected int algorithm;
	private byte[] key;
	private int plaintextLength;

	/**
	 * Creates a <code>SymmetricallyEncryptedDataOutputStream</code>
	 * and saves the arguments for later use.  In most cases
	 * <code>out</code> should be a <code>PacketOutputStream</code>.
	 *
	 * @param out the underlying output stream.
	 * @param algorithm the symmetric key algorithm to be used.
	 * @param key the key that will encrypt the data.
	 * @param length the length of the data to be written; -1 if unknown.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public SymmetricallyEncryptedDataOutputStream(
		OutputStream out,
		int algorithm,
		byte[] key,
		int length)
	{
		this(
			out,
			algorithm,
			key,
			length,
			PACKET_TAG_SYMMETRICALLY_ENCRYPTED_DATA);
	}

	/**
	 * Creates a <code>SymmetricallyEncryptedDataOutputStream</code>
	 * and saves the arguments for later use.  In most cases
	 * <code>out</code> should be a <code>PacketOutputStream</code>.
	 *
	 * @param out the underlying output stream.
	 * @param algorithm the symmetric key algorithm to be used.
	 * @param key the key that will encrypt the data.
	 * @see com.hush.pgp.PgpConstants
	 * @see com.hush.pgp.io.packets.PacketOutputStream
	 */
	public SymmetricallyEncryptedDataOutputStream(
		OutputStream out,
		int algorithm,
		byte[] key)
	{
		this(out, algorithm, key, -1);
	}

	protected SymmetricallyEncryptedDataOutputStream(
		OutputStream out,
		int algorithm,
		byte[] key,
		int plaintextLength,
		int packetTag)
	{
		super(out, packetTag);
		this.algorithm = algorithm;
		this.plaintextLength = plaintextLength;
		this.key = key;
		cipher = AlgorithmFactory.getStandardCFBBlockCipher(algorithm);
	}

	/**
	 * @see java.io.OutputStream#write(int)
	 */
	public void write(int b) throws IOException
	{
		write(new byte[] {(byte) b }, 0, 1);
	}

	/**
	 * @see java.io.OutputStream#write(byte[])
	 */
	public void write(byte[] b) throws IOException
	{
		write(b, 0, b.length);
	}

	/**
	 * @see java.io.OutputStream#write(byte[], int, int)
	 */
	public void write(byte[] b, int off, int len) throws IOException
	{
		init();
		byte[] encrypted = new byte[cipher.getOutputSize(len)];
		int encryptedLength = cipher.processBytes(b, off, len, encrypted, 0);
		if (encryptedLength > 0)
			super.write(encrypted, 0, encryptedLength);
		handleWrittenBytes(b, off, len);
	}

	/**
	 * Closes this stream and the underlying stream.
	 * 
	 * @see java.io.OutputStream#close()
	 */
	public void close() throws IOException
	{
		init();
		try
		{
			byte[] encrypted = new byte[cipher.getBlockSize()];
			int encryptedLength = cipher.doFinal(encrypted, 0);
			super.write(encrypted, 0, encryptedLength);
			super.close();
		}
		catch (InvalidCipherTextException e)
		{
			throw DataFormatException.wrap(
					"Invalid cipher text during decryption", e);
		}
	}

	/**
	 * @see com.hush.pgp.io.packets.PacketContentOutputStream#setLength(long)
	 */
	public void setLength(long length)
	{
		super.setLength(calculateLength(length));
	}

	protected long calculateLength(long length)
	{
		// We know that the cipher text length will be the plaintext length
		// plus the initial bytes for the cipher.
		return (length < 0) ? -1 : length + (cipher.getBlockSize() + 2);
	}

	protected void engineInit() throws IOException
	{
		KeyParameter keyParam;
		if (algorithm == CIPHER_3DES)
			keyParam = new DESedeParameters(key);
		else
			keyParam = new KeyParameter(key);
		super.write(engineInit2(keyParam));
		ArrayTools.wipe(key);
		key = null;
	}

	protected byte[] engineInit2(KeyParameter keyParam) throws IOException
	{
		cipher = AlgorithmFactory.getPGPCFBBlockCipher(algorithm);
		CFBParameters cfbParams = new CFBParameters(keyParam);
		cipher = AlgorithmFactory.getPGPCFBBlockCipher(algorithm);
		cipher.init(true, cfbParams);
		return cfbParams.getInitBytes();
	}

	protected void handleWrittenBytes(byte[] b, int off, int len)
	{
	}
}
