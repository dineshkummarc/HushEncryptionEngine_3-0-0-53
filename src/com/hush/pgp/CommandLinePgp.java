/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import com.hush.io.DumpInputStream;
import com.hush.pgp.io.ArmorInputStream;
import com.hush.pgp.io.ArmorOutputStream;
import com.hush.pgp.io.PgpMessageInputStream;
import com.hush.pgp.io.PgpMessageOutputStream;
import com.hush.pgp.io.packets.CompressedDataInputStream;
import com.hush.pgp.io.packets.LiteralDataInputStream;
import com.hush.pgp.io.packets.LiteralDataOutputStream;
import com.hush.pgp.io.packets.PacketInputStream;
import com.hush.pgp.io.packets.PacketOutputStream;
import com.hush.pgp.io.packets.PublicKeyInputStream;
import com.hush.pgp.io.packets.PublicSubkeyInputStream;
import com.hush.pgp.io.packets.SecretKeyInputStream;
import com.hush.pgp.io.packets.SecretSubkeyInputStream;
import com.hush.pgp.io.packets.SignatureInputStream;
import com.hush.pgp.io.packets.SymmetricallyEncryptedDataInputStream;
import com.hush.pgp.io.packets.SymmetricallyEncryptedDataOutputStream;
import com
	.hush
	.pgp
	.io
	.packets
	.SymmetricallyEncryptedIntegrityProtectedDataInputStream;
import com
	.hush
	.pgp
	.io
	.packets
	.SymmetricallyEncryptedIntegrityProtectedDataOutputStream;
import com.hush.pgp.io.packets.UserIDInputStream;
import com.hush.util.Conversions;
import com.hush.util.Logger;
import com.hush.util.UnrecoverableKeyException;

/**
 * This classes allows various command line operations to be performed.  The
 * options parallel GnuPG to a certain extent.  This class is currently suitable only
 * for the purpose of debugging the overall OpenPGP implementation.
 */
public class CommandLinePgp implements PgpConstants
{
	private static String action = null;
	private static String argument = null;
	private static String keyringFile =
		System.getProperty("HOME")
			+ File.separator
			+ ".gnupg"
			+ File.separator
			+ "pubring.gpg";
	private static Keyring keyring;

	private static String secretKeyringFile =
		System.getProperty("HOME")
			+ File.separator
			+ ".gnupg"
			+ File.separator
			+ "secring.gpg";
	private static Keyring secretKeyring;

	//private static byte[] currentPassphrase;
	public static Getopt options;

	private static int cipherAlgo = CIPHER_CAST5;
	private static int digestAlgo = HASH_MD5;

	private static int s2kCipherAlgo = CIPHER_CAST5;
	private static int s2kDigestAlgo = HASH_SHA1;
	private static int s2kMode = S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED;
	private static int s2kCount = 65536;
	// 69632 encoded 97; 65536 is encoded 96
	private static byte[] s2kSalt = null;

	public static Hashtable algorithms = new Hashtable();

	private static InputStream inStream = System.in;
	private static String inFile = null;

	private static byte[] defaultKey = null;

	private static Vector recipients = new Vector();

	private static byte[] password = null;

	private static Vector messagePasswords = new Vector();

	private static boolean sign = false;

	private static boolean publicKeyEncrypt = false;

	private static int compressionLevel = 9;

	// 0 if disable mdc
	// 1 if force mdc
	private static int specifyMdc = -1;

	private static boolean decryptOnly = false;

	private static boolean armor = false;

	static {
		algorithms.put("3DES", new Integer(CIPHER_3DES));
		algorithms.put("CAST5", new Integer(CIPHER_CAST5));
		algorithms.put("BLOWFISH", new Integer(CIPHER_BLOWFISH));
		algorithms.put("AES", new Integer(CIPHER_AES128));
		algorithms.put("AES192", new Integer(CIPHER_AES192));
		algorithms.put("AES256", new Integer(CIPHER_AES256));
		algorithms.put("TWOFISH", new Integer(CIPHER_TWOFISH));
		algorithms.put("MD5", new Integer(HASH_MD5));
		algorithms.put("SHA1", new Integer(HASH_SHA1));
		algorithms.put("RIPEMD160", new Integer(HASH_RIPEMD160));
	}

	public static void main(String[] argv) throws Throwable
	{
		LongOpt[] opts = new LongOpt[32];

		opts[0] = new LongOpt("dump-packets", LongOpt.NO_ARGUMENT, null, 0);
		opts[1] =
			new LongOpt(
				"decode-compressed-data-packet",
				LongOpt.NO_ARGUMENT,
				null,
				1);
		opts[2] = new LongOpt("infile", LongOpt.REQUIRED_ARGUMENT, null, 2);
		opts[3] =
			new LongOpt(
				"decode-symmetrically-encrypted-integrity-protected-data-packet",
				LongOpt.REQUIRED_ARGUMENT,
				null,
				3);
		opts[4] =
			new LongOpt(
				"make-symmetrically-encrypted-integrity-protected-data-packet",
				LongOpt.REQUIRED_ARGUMENT,
				null,
				4);
		opts[5] =
			new LongOpt(
				"decode-public-key-packet",
				LongOpt.NO_ARGUMENT,
				null,
				5);
		opts[6] =
			new LongOpt(
				"decode-secret-key-packet",
				LongOpt.NO_ARGUMENT,
				null,
				6);
		opts[7] =
			new LongOpt(
				"decode-signature-packet",
				LongOpt.NO_ARGUMENT,
				null,
				7);
		opts[8] = new LongOpt("unarmor", LongOpt.NO_ARGUMENT, null, 8);
		opts[9] =
			new LongOpt(
				"make-literal-data-packet",
				LongOpt.NO_ARGUMENT,
				null,
				9);
		opts[10] =
			new LongOpt(
				"make-symmetrically-encrypted-data-packet",
				LongOpt.REQUIRED_ARGUMENT,
				null,
				10);
		opts[11] =
			new LongOpt("cipher-algo", LongOpt.REQUIRED_ARGUMENT, null, 11);
		opts[12] =
			new LongOpt(
				"decode-symmetrically-encrypted-data-packet",
				LongOpt.REQUIRED_ARGUMENT,
				null,
				12);
		opts[13] = new LongOpt("make-armor", LongOpt.NO_ARGUMENT, null, 13);
		opts[14] =
			new LongOpt(
				"password-encrypt",
				LongOpt.REQUIRED_ARGUMENT,
				null,
				14);
		opts[15] =
			new LongOpt(
				"decode-literal-data-packet",
				LongOpt.NO_ARGUMENT,
				null,
				15);
		opts[16] = new LongOpt("debug", LongOpt.NO_ARGUMENT, null, 16);
		opts[17] =
			new LongOpt(
				"password-decrypt",
				LongOpt.REQUIRED_ARGUMENT,
				null,
				17);
		opts[18] =
			new LongOpt("s2k-cipher-algo", LongOpt.REQUIRED_ARGUMENT, null, 18);
		opts[19] =
			new LongOpt("s2k-digest-algo", LongOpt.REQUIRED_ARGUMENT, null, 19);
		opts[20] = new LongOpt("s2k-mode", LongOpt.REQUIRED_ARGUMENT, null, 20);
		opts[21] =
			new LongOpt("s2k-count", LongOpt.REQUIRED_ARGUMENT, null, 21);
		opts[22] =
			new LongOpt("digest-algo", LongOpt.REQUIRED_ARGUMENT, null, 22);
		opts[23] = new LongOpt("s2k-salt", LongOpt.REQUIRED_ARGUMENT, null, 23);
		opts[24] = new LongOpt("keyring", LongOpt.REQUIRED_ARGUMENT, null, 24);
		opts[25] = new LongOpt("gen-key", LongOpt.NO_ARGUMENT, null, 25);
		opts[26] =
			new LongOpt("default-key", LongOpt.REQUIRED_ARGUMENT, null, 26);
		opts[27] =
			new LongOpt("secret-keyring", LongOpt.REQUIRED_ARGUMENT, null, 27);
		opts[28] = new LongOpt("password", LongOpt.REQUIRED_ARGUMENT, null, 28);

		opts[29] = new LongOpt("disable-mdc", LongOpt.NO_ARGUMENT, null, 29);

		opts[30] = new LongOpt("decrypt-only", LongOpt.NO_ARGUMENT, null, 30);

		opts[31] = new LongOpt("armor", LongOpt.NO_ARGUMENT, null, 31);

		options =
			new Getopt(
				"Hush Command Line PGP",
				loadOptions(argv),
				"ac:er:svz:",
				opts);

		int c;
		while ((c = options.getopt()) != -1)
		{
			switch (c)
			{
				case 'a' :
					setAction("analyzePgpData", null);
					break;
				case 'z' :
					compressionLevel = Integer.parseInt(options.getOptarg());
					break;
				case 's' :
					sign = true;
					setAction("createPgpMessage", null);
					break;
				case 'r' :
					recipients.addElement(options.getOptarg());
					break;
				case 'e' :
					publicKeyEncrypt = true;
					setAction("createPgpMessage", null);
					break;
				case 'c' :
					messagePasswords.addElement(options.getOptarg().getBytes());
					setAction("createPgpMessage", null);
					break;
				case 'v' :
					Logger.setLogLevel(Logger.VERBOSE);
					break;
				case 31 :
					armor = true;
					break;
				case 30 :
					decryptOnly = true;
					break;
				case 29 :
					specifyMdc = 0;
					break;
				case 28 :
					password = options.getOptarg().getBytes();
					break;
				case 27 :
					secretKeyringFile = options.getOptarg();
					break;
				case 26 :
					defaultKey =
						Conversions.hexStringToBytes(options.getOptarg());
					break;
				case 25 :
					setAction("keyGen", null);
					break;
				case 24 :
					keyringFile = options.getOptarg();
					break;
				case 23 :
					s2kSalt = Conversions.hexStringToBytes(options.getOptarg());
					break;
				case 22 :
					digestAlgo =
						((Integer) algorithms.get(options.getOptarg()))
							.intValue();
					break;
				case 21 :
					s2kCount = Integer.parseInt(options.getOptarg());
					break;
				case 20 :
					s2kMode = Integer.parseInt(options.getOptarg());
					break;
				case 19 :
					s2kDigestAlgo =
						((Integer) algorithms.get(options.getOptarg()))
							.intValue();
					break;
				case 18 :
					s2kCipherAlgo =
						((Integer) algorithms.get(options.getOptarg()))
							.intValue();
					break;
				case 17 :
					messagePasswords.addElement(options.getOptarg().getBytes());
					break;
				case 16 :
					Logger.setLogLevel(Logger.DEBUG);
					;
					break;
				case 15 :
					setAction("decodeLiteralDataPacket", null);
					break;
				case 14 :
					messagePasswords.addElement(options.getOptarg().getBytes());
					setAction("createPgpMessage", null);
					break;
				case 13 :
					setAction("armor", null);
					break;
				case 12 :
					setAction(
						"decodeSymmetricallyEncryptedDataPacket",
						options.getOptarg());
					break;
				case 11 :
					cipherAlgo =
						((Integer) algorithms.get(options.getOptarg()))
							.intValue();
					break;
				case 10 :
					setAction(
						"makeSymmetricallyEncryptedDataPacket",
						options.getOptarg());
					break;
				case 9 :
					setAction("makeLiteralDataPacket", null);
					break;
				case 8 :
					setAction("unarmor", null);
					break;
				case 7 :
					setAction("decodeSignaturePacket", null);
					break;
				case 6 :
					setAction("decodeSecretKeyPacket", options.getOptarg());
					break;
				case 5 :
					setAction("decodePublicKeyPacket", null);
					break;
				case 4 :
					setAction(
						"makeSymmetricallyEncryptedIntegrityProtectedDataPacket",
						options.getOptarg());
					break;
				case 3 :
					setAction(
						"decodeSymmetricallyEncryptedIntegrityProtectedDataPacket",
						options.getOptarg());
					break;
				case 2 :
					inStream = new FileInputStream(options.getOptarg());
					inFile = options.getOptarg();
					break;
				case 1 :
					setAction("decodeCompressedDataPacket", null);
					break;
				case 0 :
					setAction("dumpPackets", null);
					break;
			}
		}
		loadKeyrings();
		if (action == null)
			setAction("decodePgpMessage", null);
		doAction();
		System.out.flush();
		System.out.close();
		System.gc();
	}

	private static void loadKeyrings() throws IOException
	{
		//int saveLevel = Logger.getLogLevel();
		//Logger.setLogLevel(Logger.ERROR);
		if (keyringFile != null && new File(keyringFile).exists())
		{
			keyring = new Keyring();
			keyring.load(new FileInputStream(keyringFile));
		}
		if (secretKeyringFile != null && new File(secretKeyringFile).exists())
		{
			secretKeyring = new Keyring();
			secretKeyring.load(new FileInputStream(secretKeyringFile));
		}
		//Logger.setLogLevel(saveLevel);
	}

	private static void setAction(
		String actionParameter,
		String argumentParameter)
		throws IllegalArgumentException
	{
		if (action == actionParameter)
			return;
		if (action != null)
			throw new IllegalArgumentException("Can only perform one action");
		action = actionParameter;
		argument = argumentParameter;
	}

	private static void doAction()
		throws
			NoSuchMethodException,
			IllegalAccessException,
			ClassNotFoundException,
			Throwable
	{
		try
		{
			if (argument != null)
			{
				Method actionMethod =
					Class.forName("com.hush.pgp.CommandLinePgp").getMethod(
						action,
						new Class[] { argument.getClass()});
				actionMethod.invoke(null, new Object[] { argument });
			}
			else
			{
				Method actionMethod =
					Class.forName("com.hush.pgp.CommandLinePgp").getMethod(
						action,
						new Class[0]);
				actionMethod.invoke(null, new Object[] {
				});
			}

		}
		catch (InvocationTargetException e)
		{
			throw e.getCause();
		}
	}

	public static String[] loadOptions(String[] argv)
	{

		String optionsFile =
			System.getProperty("HOME")
				+ File.separator
				+ ".gnupg"
				+ File.separator
				+ "options";
		LongOpt[] opts = new LongOpt[1];
		opts[0] = new LongOpt("options", LongOpt.REQUIRED_ARGUMENT, null, 0);
		options =
			new Getopt(
				"Hush Command Line PGP",
				(String[]) argv.clone(),
				"",
				opts);
		options.setOpterr(false);
		int c;
		while ((c = options.getopt()) != -1)
		{
			if (c == 0)
				optionsFile = options.getOptarg();
		}

		Vector options = new Vector();

		try
		{
			BufferedReader reader =
				new BufferedReader(new FileReader(optionsFile));
			String line;
			while ((line = reader.readLine()) != null)
			{
				line = line.trim();
				if (line.length() > 0 && line.charAt(0) != '#')
				{
					int spaceIndex = line.indexOf(" ");
					if (spaceIndex == -1)
					{
						options.addElement("--" + line);
					}
					else
					{
						options.addElement(
							"--" + line.substring(0, spaceIndex));
						options.addElement(line.substring(spaceIndex + 1));
					}
				}
			}

		}
		catch (FileNotFoundException e)
		{
			System.err.println("Warning: options file not found");
		}
		catch (IOException e)
		{
			System.err.println("I/O error reading options file");
		}

		for (int x = 0; x < argv.length; x++)
		{
			options.addElement(argv[x]);
		}

		String[] optionStrings = new String[options.size()];
		options.copyInto(optionStrings);

		return optionStrings;
	}

	public static void unarmor() throws Exception
	{
		ArmorInputStream pgpIn = new ArmorInputStream(inStream);
		int x;
		byte[] b = new byte[2048];
		while ((x = pgpIn.read(b)) != -1)
			System.out.write(b, 0, x);
		pgpIn.close();
	}

	public static void armor() throws Exception
	{
		ArmorOutputStream pgpOut =
			new ArmorOutputStream(System.out, ARMOR_TYPE_PGP_MESSAGE);
		int x;
		byte[] b = new byte[512];
		while ((x = inStream.read(b)) != -1)
			pgpOut.write(b, 0, x);
		pgpOut.close();
	}

	public static void makeLiteralDataPacket() throws IOException
	{
		OutputStream pgpOut;
		PacketOutputStream packetOutputStream =
			new PacketOutputStream(System.out);
		if (inFile != null)
		{
			pgpOut =
				new LiteralDataOutputStream(
					packetOutputStream,
					false,
					inFile.getBytes(),
					new File(inFile).lastModified() / 1000,
					new File(inFile).length());
		}
		else
		{
			pgpOut = new LiteralDataOutputStream(packetOutputStream);
		}

		int x;
		byte[] b = new byte[512];
		while ((x = inStream.read(b)) != -1)
		{
			pgpOut.write(b, 0, x);
		}
		pgpOut.close();
	}

	public static void makeSymmetricallyEncryptedDataPacket(String password)
		throws IOException
	{
		if (s2kSalt == null && s2kMode != S2kAlgorithm.S2K_TYPE_SIMPLE)
		{
			s2kSalt = new byte[16];
			new SecureRandom().nextBytes(s2kSalt);
		}
		S2kAlgorithm s2k =
			new S2kAlgorithm(s2kMode, s2kDigestAlgo, s2kSalt, s2kCount);
		SymmetricallyEncryptedDataOutputStream pgpOut =
			new SymmetricallyEncryptedDataOutputStream(
				new PacketOutputStream(System.out),
				cipherAlgo,
				s2k.s2k(
					password.getBytes(),
					SYMMETRIC_CIPHER_KEY_LENGTHS[cipherAlgo]));
		int x;
		byte[] b = new byte[512];
		while ((x = inStream.read(b)) != -1)
			pgpOut.write(b, 0, x);
		pgpOut.close();
	}

	public static void makeSymmetricallyEncryptedIntegrityProtectedDataPacket(String password)
		throws IOException
	{
		if (s2kSalt == null && s2kMode != S2kAlgorithm.S2K_TYPE_SIMPLE)
		{
			s2kSalt = new byte[16];
			new SecureRandom().nextBytes(s2kSalt);
		}
		S2kAlgorithm s2k =
			new S2kAlgorithm(s2kMode, s2kDigestAlgo, s2kSalt, s2kCount);
		SymmetricallyEncryptedIntegrityProtectedDataOutputStream pgpOut =
			new SymmetricallyEncryptedIntegrityProtectedDataOutputStream(
				new PacketOutputStream(System.out),
				cipherAlgo,
				s2k.s2k(
					password.getBytes(),
					SYMMETRIC_CIPHER_KEY_LENGTHS[cipherAlgo]));
		int x;
		byte[] b = new byte[512];
		while ((x = inStream.read(b)) != -1)
			pgpOut.write(b, 0, x);
		pgpOut.close();
	}

	public static void decodeLiteralDataPacket() throws IOException
	{
		InputStream pgpIn;
		pgpIn = new LiteralDataInputStream(new PacketInputStream(inStream));
		int x;
		byte[] b = new byte[512];
		while ((x = pgpIn.read(b)) != -1)
			System.out.write(b, 0, x);
	}

	public static void decodeSymmetricallyEncryptedDataPacket(String key)
		throws IOException
	{

		S2kAlgorithm s2k =
			new S2kAlgorithm(s2kMode, s2kDigestAlgo, s2kSalt, s2kCount);
		InputStream pgpIn;
		pgpIn =
			new SymmetricallyEncryptedDataInputStream(
				new PacketInputStream(inStream),
				new int[]{cipherAlgo},
				new byte[][] {
					 s2k.s2k(
						key.getBytes(),
						SYMMETRIC_CIPHER_KEY_LENGTHS[cipherAlgo])});
		int x;
		byte[] b = new byte[512];
		while ((x = pgpIn.read(b)) != -1)
			System.out.write(b, 0, x);
	}

	public static void decodeSymmetricallyEncryptedIntegrityProtectedDataPacket(String key)
		throws IOException
	{

		S2kAlgorithm s2k =
			new S2kAlgorithm(s2kMode, s2kDigestAlgo, s2kSalt, s2kCount);
		InputStream pgpIn;
		pgpIn =
			new SymmetricallyEncryptedIntegrityProtectedDataInputStream(
				new PacketInputStream(inStream),
				new int[]{cipherAlgo},
				new byte[][] {
					 s2k.s2k(
						key.getBytes(),
						SYMMETRIC_CIPHER_KEY_LENGTHS[cipherAlgo])});
		int x;
		byte[] b = new byte[512];
		while ((x = pgpIn.read(b)) != -1)
			System.out.write(b, 0, x);
	}

	public static void decodeCompressedDataPacket() throws IOException
	{
		InputStream pgpIn;
		pgpIn = new CompressedDataInputStream(new PacketInputStream(inStream));
		int x;
		byte[] b = new byte[512];
		while ((x = pgpIn.read(b)) != -1)
			System.out.write(b, 0, x);
	}

	public static void decodePublicKeyPacket() throws IOException
	{
		PublicKeyInputStream pgpIn;
		pgpIn = new PublicKeyInputStream(new PacketInputStream(inStream));
		Key key = pgpIn.getKey();
		System.out.println("Version: " + key.getVersion());
		System.out.println("Algorithm: " + key.getAlgorithm());
		System.out.println("Validity period: " + key.getKeyExpirationTime());
		System.out.println("Creation time: " + key.getCreationTime());
		CipherParameters publicKey = key.getPublicKey();
		if (publicKey instanceof RSAKeyParameters)
		{
			RSAKeyParameters rsaKey = (RSAKeyParameters) publicKey;
			System.out.println("Found RSA public key");
			System.out.println(
				"Exponent: " + rsaKey.getExponent().toString(16));
			System.out.println("Modulus: " + rsaKey.getModulus().toString(16));
		}
		else if (publicKey instanceof DSAPublicKeyParameters)
		{
			DSAPublicKeyParameters dsaKey = (DSAPublicKeyParameters) publicKey;
			DSAParameters dsaParams = dsaKey.getParameters();
			System.out.println("Found DSA public key");
			System.out.println("P: " + dsaParams.getP().toString(16));
			System.out.println("Q: " + dsaParams.getQ().toString(16));
			System.out.println("G: " + dsaParams.getG().toString(16));
			System.out.println("Y: " + dsaKey.getY().toString(16));
		}
		else if (publicKey instanceof ElGamalPublicKeyParameters)
		{
			ElGamalPublicKeyParameters elgamalKey =
				(ElGamalPublicKeyParameters) publicKey;
			ElGamalParameters elgamalParams = elgamalKey.getParameters();
			System.out.println("Found ElGamal public key");
			System.out.println("P: " + elgamalParams.getP().toString(16));
			System.out.println("G: " + elgamalParams.getG().toString(16));
			System.out.println("Y: " + elgamalKey.getY().toString(16));
		}
		System.out.println(
			"Fingerprint: "
				+ Conversions.bytesToHexString(key.getFingerprint()));
		System.out.println(
			"Key ID: " + Conversions.bytesToHexString(key.getKeyID()));
	}

	public static void decodeSignaturePacket() throws IOException
	{
		SignatureInputStream pgpIn;
		pgpIn = new SignatureInputStream(new PacketInputStream(inStream));
		Signature signature = pgpIn.getSignature();
		System.out.println("Version: " + signature.getVersion());
		System.out.println("Signature type: " + signature.getSignatureType());
		System.out.println(
			"Public key algorithm: " + signature.getPublicKeyAlgorithm());
		System.out.println("Hash algorithm: " + signature.getHashAlgorithm());
		System.out.println(
			"Creation time: " + signature.getCreationTime(false));
		System.out.println(
			"Definitive creation time: " + signature.getCreationTime(true));
		System.out.println(
			"Issuer key ID: "
				+ Conversions.bytesToHexString(signature.getIssuerKeyID(false)));
		System.out.println(
			"Definitive issuer key ID: "
				+ Conversions.bytesToHexString(signature.getIssuerKeyID(true)));
		System.out.println(
			"Key expiration time: " + signature.getCreationTime(false));
		System.out.println(
			"Definitive key expiration time: "
				+ signature.getCreationTime(true));
		System.out.println(
			"Preferred symmetric algorithms: "
				+ Conversions.bytesToHexString(
					signature.getPreferredSymmetricKeyAlgorithms(false)));
		System.out.println(
			"Definitive preferred symmetric algorithms: "
				+ Conversions.bytesToHexString(
					signature.getPreferredSymmetricKeyAlgorithms(true)));
		System.out.println(
			"Preferred hash algorithms: "
				+ Conversions.bytesToHexString(
					signature.getPreferredHashAlgorithms(false)));
		System.out.println(
			"Definitive preferred hash algorithms: "
				+ Conversions.bytesToHexString(
					signature.getPreferredHashAlgorithms(true)));
		System.out.println(
			"Preferred compression algorithms: "
				+ Conversions.bytesToHexString(
					signature.getPreferredCompressionAlgorithms(false)));
		System.out.println(
			"Definitive preferred compression algorithms: "
				+ Conversions.bytesToHexString(
					signature.getPreferredCompressionAlgorithms(true)));
		System.out.println(
			"Exportable: " + signature.getExportableCertification(false));
		System.out.println(
			"Definitive exportable: "
				+ signature.getExportableCertification(true));
		System.out.println("Revocable: " + signature.getRevocable(false));
		System.out.println(
			"Definitive revocable: " + signature.getRevocable(true));
		System.out.println(
			"Trust signature: " + signature.getTrustSignature(false));
		System.out.println(
			"Definitive trust signature: " + signature.getTrustSignature(true));
		System.out.println(
			"Regular expression: "
				+ Conversions.bytesToHexString(
					signature.getRegularExpression(false)));
		System.out.println(
			"Definitive regular expression: "
				+ Conversions.bytesToHexString(
					signature.getRegularExpression(true)));
		System.out.println("Revocation keys:");
		RevocationKeySpecifier[] keys = signature.getRevocationKeys(false);
		for (int x = 0; x < keys.length; x++)
		{
			System.out.println(" Algorithm: " + keys[x].getAlgorithm());
			System.out.println(" Sensitive: " + keys[x].getSensitive());
			System.out.println(
				" Fingerprint: "
					+ Conversions.bytesToHexString(keys[x].getFingerprint()));
		}
		System.out.println("Definitive revocation keys:");
		keys = signature.getRevocationKeys(true);
		for (int x = 0; x < keys.length; x++)
		{
			System.out.println(" Algorithm: " + keys[x].getAlgorithm());
			System.out.println(" Sensitive: " + keys[x].getSensitive());
			System.out.println(
				" Fingerprint: "
					+ Conversions.bytesToHexString(keys[x].getFingerprint()));
		}

		System.out.println("Notation data:");
		NotationData[] data = signature.getNotationData(false);
		for (int x = 0; x < data.length; x++)
		{
			System.out.println(
				" Human readable: " + data[x].getHumanReadable());
			System.out.println(" Name: " + data[x].getName());
			System.out.println(
				" Value: "
					+ (data[x].getHumanReadable()
						? new String(data[x].getValue())
						: Conversions.bytesToHexString(data[x].getValue())));
		}
		System.out.println("Definitive notation data:");
		data = signature.getNotationData(true);
		for (int x = 0; x < data.length; x++)
		{
			System.out.println(
				" Human readable: " + data[x].getHumanReadable());
			System.out.println(" Name: " + data[x].getName());
			System.out.println(
				" Value: "
					+ (data[x].getHumanReadable()
						? new String(data[x].getValue())
						: Conversions.bytesToHexString(data[x].getValue())));
		}

		System.out.println("Key server preferences:");
		KeyServerPreferences prefs = signature.getKeyServerPreferences(false);
		if (prefs != null)
			System.out.println(" No modify: " + prefs.noModify);
		System.out.println("Definitive key server preferences:");
		prefs = signature.getKeyServerPreferences(true);
		if (prefs != null)
			System.out.println(" No modify: " + prefs.noModify);

		byte[] keyserver = signature.getPreferredKeyServer(false);
		System.out.println(
			"Preferred key server: "
				+ (keyserver == null ? null : new String(keyserver)));
		keyserver = signature.getPreferredKeyServer(true);
		System.out.println(
			"Definitive preferred key server: "
				+ (keyserver == null ? null : new String(keyserver)));
		System.out.println(
			"Primary user ID: " + signature.getPrimaryUserID(false));
		System.out.println(
			"Definitive primary user ID: " + signature.getPrimaryUserID(true));
		byte[] policy = signature.getPolicyURL(false);
		System.out.println(
			"Policy URL: " + (policy == null ? null : new String(policy)));
		policy = signature.getPreferredKeyServer(true);
		System.out.println(
			"Definitive policy URL: "
				+ (policy == null ? null : new String(policy)));
		System.out.println("Key server preferences:");

		System.out.println("Key flags:");
		KeyFlags flags = signature.getKeyFlags(false);
		if (flags != null)
		{
			System.out.println(
				" Certify other keys: " + flags.certifyOtherKeys);
			System.out.println(" Sign data: " + flags.signData);
			System.out.println(
				" Encrypt communications: " + flags.encryptCommunications);
			System.out.println(" Encrypt storage: " + flags.encryptStorage);
		}
		System.out.println("Definitive key flags:");
		flags = signature.getKeyFlags(true);
		if (flags != null)
		{
			System.out.println(
				" Certify other keys: " + flags.certifyOtherKeys);
			System.out.println(" Sign data: " + flags.signData);
			System.out.println(
				" Encrypt communications: " + flags.encryptCommunications);
			System.out.println(" Encrypt storage: " + flags.encryptStorage);
		}

		byte[] signer = signature.getSignersUserID(false);
		System.out.println(
			"Signer user ID: " + (signer == null ? null : new String(signer)));
		policy = signature.getSignersUserID(true);
		System.out.println(
			"Definitive signer user ID: "
				+ (signer == null ? null : new String(signer)));

		System.out.println("Revocation reason:");
		RevocationReason reason = signature.getReasonForRevocation(false);
		if (reason != null)
		{
			System.out.println(
				" Revocation code: " + reason.getRevocationCode());
			System.out.println(" Reason: " + new String(reason.getReason()));
		}
		System.out.println("Definitive revocation reason:");
		reason = signature.getReasonForRevocation(true);
		if (reason != null)
		{
			System.out.println(
				" Revocation code: " + reason.getRevocationCode());
			System.out.println(" Reason: " + new String(reason.getReason()));
		}

		System.out.println("Features:");
		Features features = signature.getFeatures(false);
		if (features != null)
		{
			System.out.println(
				" Modification detection: " + features.modificationDetection);
		}
		System.out.println("Definitive features:");
		features = signature.getFeatures(false);
		if (reason != null)
		{
			System.out.println(
				" Modification detection: " + features.modificationDetection);
		}

		System.out.println("Revocation target:");
		SignatureTarget target = signature.getSignatureTarget(false);
		if (target != null)
		{
			System.out.println(
				" Public key algorithm: " + target.getPublicKeyAlgorithm());
			System.out.println(" Hash algorithm: " + target.getHashAlgorithm());
			System.out.println(
				" Hash: " + Conversions.bytesToHexString(target.getHash()));
		}
		System.out.println("Definitive revocation target:");
		target = signature.getSignatureTarget(false);
		if (target != null)
		{
			System.out.println(
				" Public key algorithm: " + target.getPublicKeyAlgorithm());
			System.out.println(" Hash algorithm: " + target.getHashAlgorithm());
			System.out.println(
				" Hash: " + Conversions.bytesToHexString(target.getHash()));
		}

		System.out.println(
			"Leftmost 16 bits of hash: "
				+ Conversions.bytesToHexString(
					signature.getLeftSixteenBitsOfHash()));

		MPI[] signatureMPIs = signature.getSignatureMPIs();
		for (int x = 0; x < signatureMPIs.length; x++)
		{
			System.out.println("MPI: " + signatureMPIs[x].getBigInteger());
		}

	}

	public static void decodeSecretKeyPacket() throws IOException
	{
		SecretKeyInputStream pgpIn;
		pgpIn = new SecretKeyInputStream(new PacketInputStream(inStream));
		Key key = pgpIn.getKey();
		System.out.println("Version: " + key.getVersion());
		System.out.println("Algorithm: " + key.getAlgorithm());
		System.out.println("Validity period: " + key.getKeyExpirationTime());
		System.out.println("Creation time: " + key.getCreationTime());
		CipherParameters publicKey = key.getPublicKey();
		//CipherParameters privateKey = pgpIn.getSecretKey();
		if (publicKey instanceof RSAKeyParameters)
		{
			RSAKeyParameters rsaKey = (RSAKeyParameters) publicKey;
			System.out.println("Found RSA key");
			System.out.println(
				"Public exponent: " + rsaKey.getExponent().toString(16));
			System.out.println("Modulus: " + rsaKey.getModulus().toString(16));
			//rsaKey = (RSAKeyParameters)privateKey;
			//System.out.println("Private exponent: " 
			//	+  rsaKey.getExponent().toString(16));
		}
		else if (publicKey instanceof DSAPublicKeyParameters)
		{
			DSAPublicKeyParameters dsaKey = (DSAPublicKeyParameters) publicKey;
			DSAParameters dsaParams = dsaKey.getParameters();
			System.out.println("Found DSA key");
			System.out.println("P: " + dsaParams.getP().toString(16));
			System.out.println("Q: " + dsaParams.getQ().toString(16));
			System.out.println("G: " + dsaParams.getG().toString(16));
			System.out.println("Y: " + dsaKey.getY().toString(16));
			//DSAPrivateKeyParameters dsaSecret = (DSAPrivateKeyParameters)privateKey;
			//System.out.println("X: " +  dsaSecret.getX().toString(16));
		}
		else if (publicKey instanceof ElGamalPublicKeyParameters)
		{
			ElGamalPublicKeyParameters elgamalKey =
				(ElGamalPublicKeyParameters) publicKey;
			ElGamalParameters elgamalParams = elgamalKey.getParameters();
			System.out.println("Found ElGamal public key");
			System.out.println("P: " + elgamalParams.getP().toString(16));
			System.out.println("G: " + elgamalParams.getG().toString(16));
			System.out.println("Y: " + elgamalKey.getY().toString(16));
		}
	}

	public static void setCipherAlgo(String algorithm)
	{
		cipherAlgo = ((Integer) algorithms.get(algorithm)).intValue();
	}

	public static void setDigestAlgo(String algorithm)
	{
		digestAlgo = ((Integer) algorithms.get(algorithm)).intValue();
	}

	public static void dumpPackets() throws IOException
	{
		int packetCount = 0;

		DumpInputStream inAndDump = new DumpInputStream(inStream, null);

		while (true)
		{
			FileOutputStream dump =
				new FileOutputStream("packet" + packetCount);
			inAndDump.setDumpstream(dump);
			PacketInputStream pgp = new PacketInputStream(inAndDump);
			if (pgp.getType() == -1)
			{
				System.out.println("Dumped " + packetCount + " packets");
				return;
			}
			while (pgp.read() != -1)
			{
			}
			packetCount++;
			dump.flush();
			dump.close();
		}
	}

	public static void decodePgpMessage()
		throws IOException, InvalidSignatureException, MissingSelfSignatureException
	{
		PgpMessageInputStream pgpIn = new PgpMessageInputStream(inStream);

		if (decryptOnly)
			pgpIn.decryptOnly();

		for (int x = 0; x < messagePasswords.size(); x++)
		{
			pgpIn.addPassword((byte[]) messagePasswords.elementAt(x));
		}

		Key defaultKey = getDefaultKey();

		if (defaultKey != null)
		{
			try
			{
				defaultKey.getSecretKey();
				pgpIn.addSecretKey(defaultKey);
			}
			catch (UnrecoverableKeyException e)
			{

			}
		}

		if (keyring != null)
			pgpIn.addKeyring(secretKeyring);

		byte[] b = new byte[65536];
		int x;
		while ((x = pgpIn.read(b)) != -1)
		{
			System.out.write(b, 0, x);
		}

		pgpIn.close();
		Signature[] sigs = pgpIn.getSignatures();
		for (x = 0; x < sigs.length; x++)
		{
			System.err.println(
				"Signature by: "
					+ Conversions.bytesToHexString(
						sigs[x].getIssuerKeyID(false)));
			Key publicKey = keyring.getKey(sigs[x].getIssuerKeyID(false));
			if (publicKey == null)
			{
				System.err.println(
					"No key found for: "
						+ Conversions.bytesToHexString(
							sigs[x].getIssuerKeyID(false)));
			}

			try
			{
				sigs[x].finishVerification(publicKey);

				System.err.println(
					"Signature verified by: "
						+ Conversions.bytesToHexString(
							sigs[x].getIssuerKeyID(false)));
			}
			catch (InvalidSignatureException e)
			{
				System.err.println(
					"Signature failed by: "
						+ Conversions.bytesToHexString(
							sigs[x].getIssuerKeyID(false)));
			}
		}
		pgpIn = null;
		System.gc();
	}

	public static void analyzePgpData()
		throws IOException, InvalidSignatureException, MissingSelfSignatureException
	{
		int currentPacketType;
		InputStream currentPacket;

		PushbackInputStream pushBack = new PushbackInputStream(inStream);
		int firstChar = pushBack.read();
		pushBack.unread(firstChar);

		if (firstChar == (int) '-')
		{
			inStream = new ArmorInputStream(inStream);
		}
		else
			inStream = pushBack;

		while (true)
		{
			currentPacket = new PacketInputStream(inStream);
			if ((currentPacketType =
				((PacketInputStream) currentPacket).getType())
				== -1)
			{
				return;
			}
			try
			{
				switch (currentPacketType)
				{
					case PACKET_TAG_PUBLIC_KEY :
						currentPacket = new PublicKeyInputStream(currentPacket);
						break;
					case PACKET_TAG_PUBLIC_SUBKEY :
						currentPacket =
							new PublicSubkeyInputStream(currentPacket);
						break;
					case PACKET_TAG_SECRET_KEY :
						currentPacket = new SecretKeyInputStream(currentPacket);
						break;
					case PACKET_TAG_SECRET_SUBKEY :
						currentPacket =
							new SecretSubkeyInputStream(currentPacket);
						break;
					case PACKET_TAG_SIGNATURE :
						break;
					case PACKET_TAG_USER_ID :
						currentPacket = new UserIDInputStream(currentPacket);
						break;
					case PACKET_TAG_USER_ATTRIBUTE :
						break;
					case PACKET_TAG_TRUST :
						break;
					default :
						// First packet is neither a public nor a private key packet, skip.
						//throw new DataFormatException(
						//	"Unrecognized or unexpected packet type: "
						//		+ currentPacketType);
				}
			}
			catch (IOException e)
			{
				Logger.log(
					null,
					Logger.WARNING,
					"Error handling packet of type: " + currentPacketType);
				Logger.log(
					null,
					Logger.WARNING,
					"Error message: " + e.getMessage());

			}
			while (currentPacket.read() != -1)
			{
				;
			}
		}
	}

	public static void createPgpMessage()
		throws IOException, InvalidSignatureException, MissingSelfSignatureException
	{

		if (publicKeyEncrypt && recipients.size() == 0)
		{
			System.err.println(
				"Must specify recipient for public key encryption.");
			System.exit(1);
		}

		PgpMessageOutputStream pgpOut;

		if (inFile != null)
		{
			pgpOut = new PgpMessageOutputStream(System.out, new SecureRandom());

			pgpOut.setFilename(inFile.getBytes());
			pgpOut.setTimestamp(new File(inFile).lastModified() / 1000);
			pgpOut.setLength(new File(inFile).length());
			pgpOut.setUseMdc(specifyMdc == -1 || specifyMdc == 1);
			pgpOut.setCompressionLevel(compressionLevel);
			pgpOut.setUseArmor(armor);
		}
		else
		{
			pgpOut = new PgpMessageOutputStream(System.out, new SecureRandom());
			pgpOut.setUseMdc(specifyMdc == -1 || specifyMdc == 1);
			pgpOut.setCompressionLevel(compressionLevel);
			pgpOut.setUseArmor(armor);
		}

		if (!publicKeyEncrypt && messagePasswords.size() == 0)
			pgpOut.setPlaintext(true);

		for (int x = 0; x < messagePasswords.size(); x++)
		{
			pgpOut.addPassword(
				(byte[]) messagePasswords.elementAt(x),
				s2kMode,
				s2kDigestAlgo,
				s2kCount);
		}

		Enumeration e = recipients.elements();

		while (e.hasMoreElements())
		{
			String recipient = (String) e.nextElement();

			// First, get any keys that have a user ID packet identifying them
			// as the recipient.
			Key[] tmpkeys = keyring.getKeys(recipient);
			if (tmpkeys.length == 0)
			{
				System.err.println(
					"No keys found for " + new String(recipient));
				System.exit(1);
			}

			int x;
			for (x = 0; x < tmpkeys.length; x++)
			{
				pgpOut.addRecipient(tmpkeys[x].getEncryptionKey());
			}
		}

		if (sign)
			pgpOut.addOnePassSigner(getDefaultKey());

		int x;
		byte[] b = new byte[512];
		while ((x = inStream.read(b)) != -1)
			pgpOut.write(b, 0, x);
		pgpOut.close();
	}

	public static void keyGen() throws IOException
	{
		Key newKey =
			new Key(
				4,
				System.currentTimeMillis() / 1000,
				CIPHER_RSA,
				1024,
				Key.KeyType.ENCRYPTION,
				new SecureRandom());
		System.err.println("Please enter a password:");
		String password =
			new BufferedReader(new InputStreamReader((System.in))).readLine();
		newKey.encryptSecretKeyMaterial(
			password.getBytes(),
			cipherAlgo,
			S2kAlgorithm.S2K_TYPE_ITERATED_AND_SALTED,
			digestAlgo,
			s2kCount,
			true);
	}

	private static Key getDefaultKey()
		throws IOException, MissingSelfSignatureException, InvalidSignatureException
	{
		if (defaultKey == null)
			return null;
		Key defaultKeyObj = secretKeyring.getKey(defaultKey);
		if (defaultKeyObj == null)
			throw new RuntimeException(
				"Could not find default key: "
					+ Conversions.bytesToHexString(defaultKey));
		if (password != null)
			defaultKeyObj.decryptSecretKey(password);
		return defaultKeyObj;
	}

}