/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.math.BigInteger;

/**
 * Constants used extensively are declared and defined in this interface.
 * By implementing it you get access to it directly.
 *
 * @author Magnus Hessel, Brian Smith
 */
public interface PgpConstants
{

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_IDEA = 1;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_3DES = 2;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_CAST5 = 3;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_BLOWFISH = 4;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_AES128 = 7;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_AES192 = 8;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_AES256 = 9;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.2)
	 */
	public static final int CIPHER_TWOFISH = 10;

	/**
	 * An array of strings commonly used to represent the symmetric key
	 * encryption algorithms.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final String[] SYMMETRIC_CIPHER_STRINGS =
		{
			"PLAINTEXT",
			"IDEA",
			"3DES",
			"CAST5",
			"BLOWFISH",
			"SAFER",
			"DESSK",
			"AES",
			"AES192",
			"AES256",
			"TWOFISH" };

	/**
	 * An array of key lengths for symmetric algorithm usage.  The
	 * length is in bytes.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final int[] SYMMETRIC_CIPHER_KEY_LENGTHS =
		{ -1, 16, // IDEA is 128 bits
		24, // Triple DES has 192 bit key but the actual strength is 168.
		16, // CAST5 is 128 bits./
		16, // Blowfish is 128 bits.
		-1, -1, 16, // AES 128
		24, // AES 192
		32, // AES 256
		32, // Twofish
	};

	/**
	 * An array of key lengths for symmetric algorithm usage.  The
	 * length is in bytes.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final int[] SYMMETRIC_CIPHER_BLOCK_LENGTHS =
		{ -1, -1, 8, // Triple DES
		8, // CAST5 
		8, // Blowfish 
		-1, -1, 16, // AES
		16, // AES
		16, // AES
		16, // Twofish
	};

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_RSA = 1;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_RSA_ENCRYPT_ONLY = 2;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_RSA_SIGN_ONLY = 3;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_ELGAMAL_ENCRYPT_ONLY = 16;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_DSA = 17;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_ECC = 18;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_ECDSA = 19;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_ELGAMAL = 20;

	/**
	 * Definition of a symmetric algorithm.  (RFC2440 9.1)
	 */
	public static final int CIPHER_DIFFIE_HELLMAN = 21;

	/**
	 * An array of strings commonly used to represent the symmetric key
	 * encryption algorithms.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final String[] PUBLIC_KEY_CIPHER_STRINGS =
		{
			"",
			"RSA",
			"RSA Encrypt-only",
			"RSA Sign-only",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"Elgamal Encrypt-only",
			"DSA",
			"Elliptic Curve",
			"ECDSA",
			"Elgamal",
			"Diffie-Hellman" };

	/**
	 * Definition of a hash algorithm.  (RFC2440 9.4)
	 */
	public static final int HASH_MD5 = 1;

	/**
	 * Definition of a hash algorithm.  (RFC2440 9.4)
	 */
	public static final int HASH_SHA1 = 2;

	/**
	 * Definition of a hash algorithm.  (RFC2440 9.4)
	 */
	public static final int HASH_RIPEMD160 = 3;

	/**
	 * Definition of a hash algorithm.  (RFC2440 9.4)
	 */
	public static final int HASH_SHA256 = 8;
	
	/**
	 * Definition of a hash algorithm.  (RFC2440 9.4)
	 */
	public static final int HASH_SHA384 = 9;
	
	/**
	 * Definition of a hash algorithm.  (RFC2440 9.4)
	 */
	public static final int HASH_SHA512 = 10;
	
	/**
	 * An array of output lengths for hash algorithm usage.  The
	 * length is in bytes.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final int[] HASH_LENGTHS = new int[] {
		-1,
		16, // MD5
		20, // SHA1
		20, // RipeMD160
		-1,
		-1,
		-1,
		-1,
		32, // SHA256
		48, // SHA384
		64, // SHA512
	};

	/**
	 * An array of strings commonly used to represent the hash
	 * algorithms.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final String[] HASH_STRINGS =
		new String[] { null, "MD5", "SHA1", "RIPEMD160", null, null, 
			null, null, "SHA256", "SHA384", "SHA512" };

	public static final BigInteger DEFAULT_RSA_PUBLIC_EXPONENT =
		new BigInteger("11");

	public static final int DEFAULT_RSA_PRIME_CERTAINTY = 25;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_PUBLIC_KEY_ENCRYPTED_SESSION_KEY = 1;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_SIGNATURE = 2;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY = 3;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_ONE_PASS_SIGNATURE = 4;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_SECRET_KEY = 5;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_PUBLIC_KEY = 6;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_SECRET_SUBKEY = 7;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_COMPRESSED_DATA = 8;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_SYMMETRICALLY_ENCRYPTED_DATA = 9;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_MARKER = 10;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_LITERAL_DATA = 11;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_TRUST = 12;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_USER_ID = 13;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_PUBLIC_SUBKEY = 14;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_USER_ATTRIBUTE = 17;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA =
		18;

	/**
	 * Packet tag definition.  (RFC2440 4.3)
	 */
	public static final int PACKET_TAG_MODIFICATION_DETECTION_CODE = 19;

	/**
	 * A wild card Key ID.  (RFC2440 5.1)
	 */
	byte[] WILD_CARD_KEY_ID =
		new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// Armour headers (not final, so they may be overridden if necessary

	/**
	 * PGP armor type.
	 */
	public static final int ARMOR_TYPE_PGP_MESSAGE = 0;

	/**
	 * PGP armor header. "-----BEGIN PGP MESSAGE-----"
	 */
	public static final byte[] ARMOR_HEADER_PGP_MESSAGE =
		{
			45,
			45,
			45,
			45,
			45,
			66,
			69,
			71,
			73,
			78,
			32,
			80,
			71,
			80,
			32,
			77,
			69,
			83,
			83,
			65,
			71,
			69,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor footer. "-----END PGP MESSAGE-----"
	 */
	public static final byte[] ARMOR_FOOTER_PGP_MESSAGE =
		{
			45,
			45,
			45,
			45,
			45,
			69,
			78,
			68,
			32,
			80,
			71,
			80,
			32,
			77,
			69,
			83,
			83,
			65,
			71,
			69,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor type.
	 */
	public static final int ARMOR_TYPE_PGP_SIGNED_MESSAGE = 1;

	/**
	 * PGP armor header. "-----BEGIN PGP SIGNED MESSAGE-----"
	 */
	public static final byte[] ARMOR_HEADER_PGP_SIGNED_MESSAGE =
		{
			45,
			45,
			45,
			45,
			45,
			66,
			69,
			71,
			73,
			78,
			32,
			80,
			71,
			80,
			32,
			83,
			73,
			71,
			78,
			69,
			68,
			32,
			77,
			69,
			83,
			83,
			65,
			71,
			69,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor type.
	 */
	public static final int ARMOR_TYPE_PGP_SIGNATURE = 2;

	/**
	 * PGP armor header. "-----BEGIN PGP SIGNATURE-----"
	 */
	public static final byte[] ARMOR_HEADER_PGP_SIGNATURE =
		{
			45,
			45,
			45,
			45,
			45,
			66,
			69,
			71,
			73,
			78,
			32,
			80,
			71,
			80,
			32,
			83,
			73,
			71,
			78,
			65,
			84,
			85,
			82,
			69,
			45,
			45,
			45,
			45,
			45 };

	public static final String ARMOR_HEADER_PGP_SIGNATURE_STRING
		= new String(ARMOR_HEADER_PGP_SIGNATURE);
	
	/**
	 * PGP armor footer. "-----END PGP SIGNATURE-----"
	 */
	public static final byte[] ARMOR_FOOTER_PGP_SIGNATURE =
		{
			45,
			45,
			45,
			45,
			45,
			69,
			78,
			68,
			32,
			80,
			71,
			80,
			32,
			83,
			73,
			71,
			78,
			65,
			84,
			85,
			82,
			69,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor type.
	 */
	public static final int ARMOR_TYPE_PGP_PUBLIC_KEY = 3;

	/**
	 * PGP armor header. "-----BEGIN PGP PUBLIC KEY-----"
	 */
	public static final byte[] ARMOR_HEADER_PGP_PUBLIC_KEY =
		{
			45,
			45,
			45,
			45,
			45,
			66,
			69,
			71,
			73,
			78,
			32,
			80,
			71,
			80,
			32,
			80,
			85,
			66,
			76,
			73,
			67,
			32,
			75,
			69,
			89,
			32,
			66,
			76,
			79,
			67,
			75,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor footer. "-----END PGP PUBLIC KEY-----"
	 */
	public static final byte[] ARMOR_FOOTER_PGP_PUBLIC_KEY =
		{
			45,
			45,
			45,
			45,
			45,
			69,
			78,
			68,
			32,
			80,
			71,
			80,
			32,
			80,
			85,
			66,
			76,
			73,
			67,
			32,
			75,
			69,
			89,
			32,
			66,
			76,
			79,
			67,
			75,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor type.
	 */
	public static final int ARMOR_TYPE_PGP_PRIVATE_KEY = 4;

	/**
	 * PGP armor header. "-----BEGIN PGP PRIVATE KEY-----"
	 */
	public static final byte[] ARMOR_HEADER_PGP_PRIVATE_KEY =
		{
			45,
			45,
			45,
			45,
			45,
			66,
			69,
			71,
			73,
			78,
			32,
			80,
			71,
			80,
			32,
			80,
			82,
			73,
			86,
			65,
			84,
			69,
			32,
			75,
			69,
			89,
			32,
			66,
			76,
			79,
			67,
			75,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * PGP armor footer. "-----END PGP PRIVATE KEY-----"
	 */
	public static final byte[] ARMOR_FOOTER_PGP_PRIVATE_KEY =
		{
			45,
			45,
			45,
			45,
			45,
			69,
			78,
			68,
			32,
			80,
			71,
			80,
			32,
			80,
			82,
			73,
			86,
			65,
			84,
			69,
			32,
			75,
			69,
			89,
			32,
			66,
			76,
			79,
			67,
			75,
			45,
			45,
			45,
			45,
			45 };

	/**
	 * A constant for a CRLF.  (\x0a\x0d)
	 */
	public static final byte[] CRLF = { 13, 10 };

	/**
	 * Value for computing armor checksums.  
	 */
	public static final long ARMOR_CRC_INIT = 0xb704ceL;
	public static final long ARMOR_CRC_POLY = 0x1864cfbL;

	/**
	 * Compression algorithm definition.
	 */
	public static final int COMPRESSION_ALGORITHM_UNCOMPRESSED = 0x0;

	/**
	 * Compression algorithm definition.
	 */
	public static final int COMPRESSION_ALGORITHM_ZIP = 0x01;

	/**
	 * Compression algorithm definition.
	 */
	public static final int COMPRESSION_ALGORITHM_ZLIB = 0x02;

	/**
	 * An array of strings commonly used to represent the compression
	 * algorithms.  The array is indexed by the constants that
	 * represent the algorithms.
	 */
	public static final String[] COMPRESSION_ALGORITHM_STRINGS =
		new String[] { "Uncompressed", "ZIP", "ZLIB" };

	/**
	 * UTF8 character encoding constant, compatible with all Java
	 * environments.
	 */
	public static final String UTF8 = "UTF8";

	/**
	 * UTF8 character encoding constant, not compatible with Microsoft Java
	 * environment.
	 */
	public static final String UTF8_ALTERNATE = "UTF-8";

	/**
	 * Armor header key.
	 */
	public static final String ARMOR_HEADER_KEY_CHARSET = "Charset";

	/**
	 * Armor header key.
	 */
	public static final String ARMOR_HEADER_KEY_HASH = "Hash";

	/**
	 * Armor header key.
	 */
	public static final String ARMOR_HEADER_KEY_VERSION = "Version";

	/**
	 * Armor header key.
	 */
	public static final String ARMOR_HEADER_KEY_MESSAGE_ID = "MessageID";

	/**
	 * Armor header key.
	 */
	public static final String ARMOR_HEADER_KEY_COMMENT = "Comment";

	/**
	 * The current version of these libraries.
	 */
	public static final String VERSION = "Hush 3.0";

	/**
	 * 10 to the power of 20.  The standard number of iterations for S2K
	 * in Hush software.
	 */
	public static final int DEFAULT_S2K_ITERATION_COUNT = 1048576;

	/**
	 * ASN.1 prefixes used before the hash values in RSA signatures.
	 * The array is indexed by the constants that
	 * represent the hash algorithms.
	 */
	public static final byte[][] RSA_SIGNATURE_HASH_PREFIXES =
		new byte[][] {
			null,
			new byte[] {
				0x30,
				0x20,
				0x30,
				0x0C,
				0x06,
				0x08,
				0x2A,
				(byte) 0x86,
				0x48,
				(byte) 0x86,
				(byte) 0xF7,
				0x0D,
				0x02,
				0x05,
				0x05,
				0x00,
				0x04,
				0x10 },
			new byte[] {
				0x30,
				0x21,
				0x30,
				0x09,
				0x06,
				0x05,
				0x2b,
				0x0E,
				0x03,
				0x02,
				0x1A,
				0x05,
				0x00,
				0x04,
				0x14 },
			new byte[] {
				0x30,
				0x21,
				0x30,
				0x09,
				0x06,
				0x05,
				0x2B,
				0x24,
				0x03,
				0x02,
				0x01,
				0x05,
				0x00,
				0x04,
				0x14 },
			null,
			null,
			null,
			null,
			new byte[] {
				0x30,
				0x31,
				0x30,
				0x0d,
				0x06,
				0x09,
				0x60,
				(byte) 0x86,
				0x48,
				0x01,
				0x65,
				0x03,
				0x04,
				0x02,
				0x01,
				0x05,
				0x00,
				0x04,
				0x20 },
			new byte[] {
				0x30,
				0x41,
				0x30,
				0x0d,
				0x06,
				0x09,
				0x60,
				(byte) 0x86,
				0x48,
				0x01,
				0x65,
				0x03,
				0x04,
				0x02,
				0x02,
				0x05,
				0x00,
				0x04,
				0x30 },
			new byte[] {
				0x30,
				0x51,
				0x30,
				0x0d,
				0x06,
				0x09,
				0x60,
				(byte) 0x86,
				0x48,
				0x01,
				0x65,
				0x03,
				0x04,
				0x02,
				0x03,
				0x05,
				0x00,
				0x04,
				0x40 }
	};

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_CERTIFICATION_CASUAL = 0x12;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_CERTIFICATION_GENERIC = 0x10;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_CERTIFICATION_PERSONA = 0x11;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_CERTIFICATION_POSITIVE = 0x13;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_CERTIFICATION_REVOCATION = 0x30;

	/**
	 * An array of signature type definitions used for certification.
	 */
	public static int[] SIGNATURE_CERTIFICATIONS =
		new int[] {
			SIGNATURE_CERTIFICATION_GENERIC,
			SIGNATURE_CERTIFICATION_PERSONA,
			SIGNATURE_CERTIFICATION_CASUAL,
			SIGNATURE_CERTIFICATION_POSITIVE };

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_DIRECTLY_ON_KEY = 0x1f;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_KEY_REVOCATION = 0x20;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_ON_BINARY_DOCUMENT = 0x00;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_ON_CANONICAL_TEXT = 0x01;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_STANDALONE = 0x02;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_SUBKEY_BINDING = 0x18;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_SUBKEY_REVOCATION = 0x28;

	/**
	 * Signature type definition.  (RFC2440 5.2.1)
	 */
	public static final int SIGNATURE_TIMESTAMP = 0x40;

	/**
	 * Definition of an S2K type.
	 */
	public static final int S2K_TYPE_SIMPLE = 0;

	/**
	 * Definition of an S2K type.
	 */
	public static final int S2K_TYPE_SALTED = 1;

	/**
	 * Definition of an S2K type.
	 */
	public static final int S2K_TYPE_ITERATED_AND_SALTED = 3;
}
