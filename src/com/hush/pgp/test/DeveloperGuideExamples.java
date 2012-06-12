/*
 * Created on Sep 25, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package com.hush.pgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.SecureRandom;

import com.hush.pgp.CanonicalSignedMessage;
import com.hush.pgp.InvalidSignatureException;
import com.hush.pgp.Key;
import com.hush.pgp.KeyGenerator;
import com.hush.pgp.Keyring;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.Signature;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;

/**
 * This class contains code corresponding to the examples in the 
 * Hush OpenPGP Developers Guide.
 */
public class DeveloperGuideExamples
{

	public static void main(String argv[]) throws Exception
	{
		FileInputStream fileStream =
			new FileInputStream("pgptest/secring.gpg ");
		SecureRandom random = new SecureRandom();

		// -- Importing and using keys
		Keyring myKeyring = new Keyring();
		myKeyring.load(fileStream);

		// -- Generating keys
		KeyGenerator myKeyGenerator = new KeyGenerator(random);
		myKeyGenerator.addPreferredSymmetricAlgorithm(
			PgpConstants.CIPHER_AES256);
		myKeyGenerator.addPreferredSymmetricAlgorithm(
			PgpConstants.CIPHER_TWOFISH);
		Key myKey =
			myKeyGenerator.generateKey(
				"mynewkey@openpgp.hush.com",
				"my passphrase".getBytes());

		Keyring myNewKeyring = new Keyring();
		myNewKeyring.addKey(myKey);
		System.out.println(myNewKeyring.toString());

		Key myRSAKey =
			new Key(
				4,
				System.currentTimeMillis() / 1000,
				PgpConstants.CIPHER_RSA,
				1024,
				Key.KeyType.BOTH,
				random);
		Signature mySig = new Signature();

		// Any number of flags can be set on the signature here
		mySig.setPreferredSymmetricAlgorithms(
			new byte[] {
				PgpConstants.CIPHER_AES256,
				PgpConstants.CIPHER_TWOFISH },
			true,
			false);

		myRSAKey.sign(
			mySig,
			myRSAKey,
			PgpConstants.SIGNATURE_DIRECTLY_ON_KEY,
			System.currentTimeMillis() / 1000,
			random);

		// -- Encrypting Data
		ByteArrayOutputStream pgpMessageBuffer = new ByteArrayOutputStream();
		PgpMessageOutputStream pgpOut =
			new PgpMessageOutputStream(pgpMessageBuffer, random);
		pgpOut.setUseArmor(true);
		pgpOut.addRecipient(myKey);
		pgpOut.write("my message\r\n".getBytes());
		pgpOut.close();
		System.out.write(pgpMessageBuffer.toByteArray());

		// Store the output for later decryption
		byte[] encryptedMessage = pgpMessageBuffer.toByteArray();

		pgpMessageBuffer = new ByteArrayOutputStream();
		pgpOut = new PgpMessageOutputStream(pgpMessageBuffer, random);
		pgpOut.setUseArmor(true);
		pgpOut.setSymmetricCipher(PgpConstants.CIPHER_TWOFISH);
		pgpOut.addPassword("my password".getBytes());
		pgpOut.write("my message\r\n".getBytes());
		pgpOut.close();
		System.out.write(pgpMessageBuffer.toByteArray());

		// -- Decrypting Data
		PgpMessageInputStream pgpIn =
			new PgpMessageInputStream(
				new ByteArrayInputStream(encryptedMessage));
		pgpIn.addKeyring(myNewKeyring);
		byte[] b = new byte[1024];
		int x;
		while ((x = pgpIn.read(b)) != -1)
		{
			System.out.write(b, 0, x);
		}

		// -- Creating a Signature on Binary Data
		pgpMessageBuffer = new ByteArrayOutputStream();
		pgpOut = new PgpMessageOutputStream(pgpMessageBuffer, random);
		pgpOut.setUseArmor(true);
		pgpOut.addRecipient(myKey);
		pgpOut.addOnePassSigner(myKey);
		pgpOut.write("my message\r\n".getBytes());
		pgpOut.close();
		System.out.write(pgpMessageBuffer.toByteArray());

		pgpIn =
			new PgpMessageInputStream(
				new ByteArrayInputStream(pgpMessageBuffer.toByteArray()));
		pgpIn.addKeyring(myNewKeyring);
		b = new byte[1024];
		while ((x = pgpIn.read(b)) != -1)
		{
			System.out.write(b, 0, x);
		}
		pgpIn.close();
		Signature[] mySignatures = pgpIn.getSignatures();
		if (mySignatures.length != 1)
		{
			System.out.println("expected to find exactly one signature");
		}
		else
		{
			try
			{
				mySignatures[0].finishVerification(myKey);
				System.out.println("verification succeeded");
			}
			catch (InvalidSignatureException e)
			{
				System.out.println("verification failed");
			}
		}

		// -- Creating a Detached Signature
		Signature mySignature = new Signature();
		mySignature.startSigning(
			myKey,
			Signature.SIGNATURE_ON_BINARY_DOCUMENT,
			System.currentTimeMillis() / 1000);
		mySignature.update("my message\r\n".getBytes());
		mySignature.finishSigning(random);
		String mySignatureString = mySignature.toString();
		System.out.println(mySignatureString);

		// -- Verifying a Detached Signature
		mySignatures =
			Signature.load(
				new ByteArrayInputStream(mySignatureString.getBytes()));
		if (mySignatures.length != 1)
		{
			System.out.println("expected to find exactly one signature");
		}
		else
		{
			mySignature = mySignatures[0];
			mySignature.startVerification();
			mySignature.update("my message\r\n".getBytes());
			try
			{
				mySignature.finishVerification(myKey);
				System.out.println("verification succeeded");
			}
			catch (InvalidSignatureException e)
			{
				System.out.println("verification failed");
			}
		}

		// -- Creating a Canonical Signed Text Message
		CanonicalSignedMessage mySignedMessage = new CanonicalSignedMessage();
		mySignedMessage.setText("this is my message\r\n");
		mySignedMessage.signMessage(
			myKey,
			random,
			System.currentTimeMillis() / 1000);
		String mySignedMessageString = mySignedMessage.getSignedMessage();
		System.out.println(mySignedMessageString);

		// -- Verifying a Canonical Signed Text Message
		mySignedMessage = new CanonicalSignedMessage();
		mySignedMessage.setSignedMessage(mySignedMessageString);
		try
		{
			Signature[] verifiedSigs =
				mySignedMessage.verifySignatures(myKey, true);
			if (verifiedSigs.length > 0)
			{
				System.out.println("verification succeeded");
			}
			else
			{
				System.out.println(
					"No signatures by the specified key were found");
			}
		}
		catch (InvalidSignatureException e)
		{
			System.out.println("verification failed");
		}

	}
}
