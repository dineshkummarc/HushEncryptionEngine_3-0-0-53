package com.hush.hee;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import com.hush.pgp.DataFormatException;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Keyring;
import com.hush.pgp.MissingSelfSignatureException;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.S2kAlgorithm;
import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.pgp.io.packets.CompressedDataInputStream;
import com.hush.pgp.io.packets.PacketInputStream;
import com.hush.util.Conversions;
import com.hush.util.ExceptionWrapper;
import com.hush.util.UnrecoverableKeyException;

public class EncryptedPrivateKeyPackage
{
	public static Keyring decryptPrivateKeyPackage(String privateKeyPackage,
			String passphrase) throws DataFormatException, IOException,
			UnrecoverableKeyException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		Keyring keyring = new Keyring();
		keyring.setVerifySelfSignatures(false);
		decryptPrivateKeyPackage(privateKeyPackage, passphrase, keyring);
		return keyring;
	}

	public static void decryptPrivateKeyPackage(String privateKeyPackage,
			String passphrase, Keyring keyring) throws DataFormatException,
			IOException, UnrecoverableKeyException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		decryptPrivateKeyPackage(Conversions.stringToByteArray(
				privateKeyPackage, PgpConstants.UTF8), Conversions
				.stringToByteArray(passphrase, PgpConstants.UTF8),
				keyring);
	}

	public static void decryptPrivateKeyPackage(String privateKeyPackage,
			byte[] passphrase, Keyring keyring) throws DataFormatException,
			IOException, UnrecoverableKeyException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		decryptPrivateKeyPackage(Conversions.stringToByteArray(
				privateKeyPackage, PgpConstants.UTF8), passphrase, keyring);
	}

	public static Keyring decryptPrivateKeyPackage(byte[] privateKeyPackage,
			byte[] passphrase) throws DataFormatException, IOException,
			UnrecoverableKeyException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		Keyring keyring = new Keyring();
		keyring.setVerifySelfSignatures(false);
		decryptPrivateKeyPackage(privateKeyPackage, passphrase, keyring);
		return keyring;
	}

	public static void decryptPrivateKeyPackage(byte[] privateKeyPackage,
			byte[] passphrase, Keyring keyring) throws DataFormatException,
			IOException, UnrecoverableKeyException, InvalidSignatureException,
			MissingSelfSignatureException
	{
		PgpMessageInputStream decryptionStream = new PgpMessageInputStream(
				new ArmorInputStream(
						new ByteArrayInputStream(privateKeyPackage)));

		decryptionStream.decryptOnly();
		decryptionStream.addPassword(passphrase);

		// For old encryptions that may have been done with the
		// wrong character encoding
		decryptionStream.addPassword(Conversions.byteArrayToString(passphrase,
				PgpConstants.UTF8).getBytes());

		keyring.load(new CompressedDataInputStream(new PacketInputStream(
				decryptionStream)));

		// Necessary to ensure that the MDC is read and verified.
		decryptionStream.close();

		keyring.decryptSecretKeys(passphrase);
	}

	public static String makePrivateKeyPackage(Keyring keyring,
			byte[] passphrase)
	{
		return makePrivateKeyPackage(keyring, passphrase, new SecureRandom(),
				PgpConstants.CIPHER_AES256, PgpConstants.HASH_SHA256, 65536);
	}

	public static String makePrivateKeyPackage(Keyring keyring,
			byte[] passphrase, SecureRandom random, int symmetricCipher,
			int hashAlgorithm, int s2kCount)
	{
		try
		{

			// Encrypt or re-encrypt the key.
			ByteArrayOutputStream keyBytes = new ByteArrayOutputStream();

			PgpMessageOutputStream keyOut = new PgpMessageOutputStream(
					keyBytes, random);

			// This is so Hush Messenger (still using old HEE) won't break
			// 2004-03-31
			keyOut.setUseMdc(false);

			keyOut.setSymmetricCipher(symmetricCipher);

			keyOut.setNoLiteral(true);

			keyOut.setUseArmor(true);

			keyOut.addPassword(passphrase,
					S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED, hashAlgorithm,
					s2kCount);

			keyring.save(keyOut, false, true);
			keyOut.close();
			keyBytes.close();
			return Conversions.byteArrayToString(keyBytes.toByteArray(),
					PgpConstants.UTF8);
		}
		catch (IOException e)
		{
			// This should never happen
			throw ExceptionWrapper.wrapInRuntimeException("This should never happen", e);
		}
	}
}
