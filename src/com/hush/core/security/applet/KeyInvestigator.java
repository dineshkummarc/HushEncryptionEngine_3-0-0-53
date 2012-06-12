/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.core.security.applet;

import java.applet.Applet;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Enumeration;

import netscape.javascript.JSObject;

import com.hush.hee.HushEncryptionEngineCore;
import com.hush.hee.IteratedAndSaltedPrivateAliasDefinition;
import com.hush.hee.KeyManagementServices;
import com.hush.hee.KeyRecord;
import com.hush.hee.keyserver.PrivateKey;
import com.hush.hee.keyserver.PrivateKeyInformation;
import com.hush.hee.keyserver.PublicKey;
import com.hush.hee.net.KeyserverClient;
import com.hush.hee.net.MailServerUpdateRequest;
import com.hush.hee.net.PuKUpdateRequest;
import com.hush.hee.net.PvKLookupRequest;
import com.hush.io.DumpInputStream;
import com.hush.pgp.Keyring;
import com.hush.pgp.MPI;
import com.hush.pgp.PgpConstants;
import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.pgp.io.packets.CompressedDataInputStream;
import com.hush.pgp.io.packets.PacketInputStream;
import com.hush.util.Conversions;

/*
 * Created on Aug 19, 2003
 * 
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */

/**
 * @author bsmith
 * 
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
public class KeyInvestigator extends Applet implements PgpConstants
{
	KeyManagementServices kms;
	KeyserverClient keyserverClient;

	public void initKeyserver()
	{
		kms = new HushEncryptionEngineCore().getKms();
	}

	public void init()
	{
		System.err.println("KeyInvestigator applet initializing...");
		initKeyserver();
		try
		{
			JSObject window = JSObject.getWindow(this);
			// Gets the applet frame window
			window.eval(getParameter("onLoad"));
		}
		catch (Throwable t)
		{
			new JSException(t);
		}
	}

	public String investigateKeys(String username, String passphrase)
	{
		return investigateKeysImpl(username, Conversions.stringToByteArray(
				passphrase, UTF8));
	}

	public static boolean getLastError()
	{
		return JSException.getLastError();
	}

	public static String getLastErrorMsg()
	{
		return JSException.getLastErrorMsg();
	}

	public static void resetLastError()
	{
		JSException.resetLastError();
	}

	public String investigateKeysImpl(String alias, byte[] passphrase)
	{
		StringBuffer result = new StringBuffer();
		try
		{
			result.append("Alias: ");
			result.append(alias);
			result.append("\r\n");

			KeyRecord record = new KeyRecord();
			record.alias = alias;
			kms.getPrivateAliasDefinition(record);
			
			String privateAlias = KeyManagementServices.makePrivateAlias(alias,
					passphrase, record.privateAliasHash, record.privateAliasIterationCount);
			result.append("Private alias: ");
			result.append(privateAlias);
			result.append("\r\n\r\n");
			
			PrivateKeyInformation pvk = keyserverClient
					.getPrivateKeyInformation(privateAlias, false);

			PrivateKey[] encryptedPrivateKeys = pvk.getEncryptedPrivateKeys();
			String encryptedPrivateKey = (String) encryptedPrivateKeys[0]
					.getEncryptedPrivateKey();
			dumpPackets(getStreamFromKey(encryptedPrivateKey, passphrase),
					result);
		}
		catch (Throwable t)
		{
			ByteArrayOutputStream throwableDump = new ByteArrayOutputStream();
			PrintStream printer = new PrintStream(throwableDump);
			t.printStackTrace(printer);
			printer.close();
			result.append("\r\n\r\n"
					+ Conversions.byteArrayToString(
							throwableDump.toByteArray(), UTF8));
			new JSException(t);
		}
		return result.toString();
	}

	public static void dumpPackets(InputStream inStream, StringBuffer result)
			throws IOException
	{
		int packetCount = 0;

		DumpInputStream inAndDump = new DumpInputStream(inStream, null);

		while (true)
		{
			ByteArrayOutputStream dump = new ByteArrayOutputStream();
			inAndDump.setDumpstream(dump);
			PacketInputStream pgp = new PacketInputStream(inAndDump);
			int type;
			if ((type = pgp.getType()) == -1)
			{
				break;
			}
			result.append("Packet type: ");
			result.append(type);
			result.append("\r\n");
			while (pgp.read() != -1)
			{
			}
			packetCount++;
			dump.flush();
			byte[] packet = dump.toByteArray();

			if (type == 7 || type == 5)
			{

				if ((packet[0] & 64) != 0)
				{
					result.append("Expected old format packet");
					return;
				}
				int lengthType = packet[0] & 3;
				int offset = 0;

				switch (lengthType)
				{
				case 0:
					offset = 2;
					break;
				case 1:
					offset = 3;
					break;
				case 2:
					offset = 5;
					break;
				case 3:
					result.append("Unsupported length type: ");
					result.append(lengthType);
					result.append("\r\n");
					return;
				}

				offset += 6;

				int algorithm = packet[offset - 1];

				int mpiCount;
				switch (algorithm)
				{
				case CIPHER_RSA:
				case CIPHER_RSA_ENCRYPT_ONLY:
				case CIPHER_RSA_SIGN_ONLY:
					mpiCount = 2;
					break;
				case CIPHER_DSA:
					mpiCount = 4;
					break;
				case CIPHER_ELGAMAL:
				case CIPHER_ELGAMAL_ENCRYPT_ONLY:
					mpiCount = 3;
					break;
				default:
					result.append("Unsupported algorithm: ");
					result.append(algorithm);
					result.append("\r\n");
					return;
				}

				for (int x = 0; x < mpiCount; x++)
				{
					MPI mpi = new MPI(packet, offset);
					offset += mpi.getLength();
				}

				// Skip an octet for the indication as to whether or not the
				// private
				// key is encrypted
				offset++;

				switch (algorithm)
				{
				case CIPHER_RSA:
				case CIPHER_RSA_ENCRYPT_ONLY:
				case CIPHER_RSA_SIGN_ONLY:
					mpiCount = 4;
					break;
				case CIPHER_DSA:
					mpiCount = 1;
					break;
				case CIPHER_ELGAMAL:
				case CIPHER_ELGAMAL_ENCRYPT_ONLY:
					mpiCount = 1;
					break;
				default:
					result.append("Unsupported algorithm: ");
					result.append(algorithm);
					result.append("\r\n");
					return;
				}

				for (int x = 0; x < mpiCount; x++)
				{
					MPI mpi = new MPI(packet, offset);

					int mpiLength = mpi.getLength();
					
					for (int y = offset + 2; y < offset + mpiLength; y++)
					{
						packet[y] = (byte) 0xFF;
					}

					offset += mpiLength;
				}

			}
			result.append("Packet: ");
			result.append(Conversions.bytesToHexString(packet));
			result.append("\r\n\r\n");
		}
	}

	public static InputStream getStreamFromKey(String encryptedPrivateKey,
			byte[] passphrase)
	{
		PgpMessageInputStream decryptionStream = new PgpMessageInputStream(
				new ArmorInputStream(new ByteArrayInputStream(Conversions
						.stringToByteArray(encryptedPrivateKey, UTF8))));

		decryptionStream.decryptOnly();
		decryptionStream.addPassword(passphrase);

		// For old encryptions that may have been done with the
		// wrong character encoding
		decryptionStream.addPassword(Conversions.byteArrayToString(passphrase,
				UTF8).getBytes());

		CompressedDataInputStream keyStream = new CompressedDataInputStream(
				new PacketInputStream(decryptionStream));
		return keyStream;
	}

	public String generatePublicKeyFromPrivateKey(String alias,
			String passphraseString)
	{
		StringBuffer result = new StringBuffer();
		try
		{
			byte[] passphrase = Conversions.stringToByteArray(passphraseString,
					UTF8);

			result.append("Alias: ");
			result.append(alias);
			result.append("\r\n");

			KeyRecord record = new KeyRecord();
			record.alias = alias;
			kms.getPrivateAliasDefinition(record);
			
			String privateAlias = KeyManagementServices.makePrivateAlias(alias,
					passphrase, record.privateAliasHash, record.privateAliasIterationCount);
			result.append("Private alias: ");
			result.append(privateAlias);
			result.append("\r\n\r\n");
			PrivateKeyInformation pvk = keyserverClient
					.getPrivateKeyInformation(privateAlias, false);

			PrivateKey[] encryptedPrivateKeys = pvk.getEncryptedPrivateKeys();

			Keyring keyring = new Keyring();

			for (int x=0; x<encryptedPrivateKeys.length; x++)
			{
				String privateKey = (String) encryptedPrivateKeys[x].getEncryptedPrivateKey();
				PgpMessageInputStream decryptionStream = new PgpMessageInputStream(
						new ArmorInputStream(
								new ByteArrayInputStream(Conversions
										.stringToByteArray(privateKey, UTF8))));

				decryptionStream.decryptOnly();
				decryptionStream.addPassword(passphrase);

				// For old encryptions that may have been done with the
				// wrong character encoding
				decryptionStream.addPassword(Conversions.byteArrayToString(
						passphrase, UTF8).getBytes());

				keyring.load(new CompressedDataInputStream(
						new PacketInputStream(decryptionStream)));
			}

			PublicKey publicKey = new PublicKey();
			publicKey.setKey(keyring.toString(false));
			publicKey.setKeyID(Conversions.bytesToHexString((keyring
					.getKeys(alias))[0].getKeyID()));

			keyserverClient.savePublicKeyInformation(alias, new PublicKey[]
			{ publicKey }, null, kms.getCustomerID(), "0",
					new IteratedAndSaltedPrivateAliasDefinition(
							PgpConstants.HASH_STRINGS[record.privateAliasHash],
							new Integer(record.privateAliasIterationCount),
							"Hex").toString(), "Encrypt", null);
			result.append("Public Key Saved\r\n\r\n");
		}
		catch (Throwable t)
		{
			ByteArrayOutputStream throwableDump = new ByteArrayOutputStream();
			PrintStream printer = new PrintStream(throwableDump);
			t.printStackTrace(printer);
			printer.close();
			result.append("\r\n\r\n"
					+ Conversions.byteArrayToString(
							throwableDump.toByteArray(), UTF8));
			new JSException(t);
		}
		return result.toString();
	}

	public static String escapeAlias(String alias)
	{
		alias = alias.trim().toLowerCase();
		char[] aliasChars = alias.toCharArray();
		StringBuffer result = new StringBuffer();
		for (int x = 0; x < aliasChars.length; x++)
		{
			result
					.append(Character.isLetterOrDigit(aliasChars[x]) ? new Character(
							aliasChars[x]).toString()
							: ("_" + Conversions.bytesToHexString(new byte[]
							{ (byte) aliasChars[x] })));
		}
		return result.toString();
	}

}
