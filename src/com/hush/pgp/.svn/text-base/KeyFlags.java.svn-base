/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

package com.hush.pgp;

import java.io.Serializable;

/**
 * A holder for key flags as described in RFC 2440 5.2.3.21.  All values default
 * to false.
 *
 * @author Brian Smith
 */
public class KeyFlags implements Serializable
{
	private static final long serialVersionUID = 431099936253684388L;

	/**
	 * Definition of a key flag.  (RFC 2440 5.2.3.21)
	 */
	public static final int CERTIFY_OTHER_KEYS = 0x01;

	/**
	 * Definition of a key flag.  (RFC 2440 5.2.3.21)
	 */
	public static final int SIGN_DATA = 0x02;

	/**
	 * Definition of a key flag.  (RFC 2440 5.2.3.21)
	 */
	public static final int ENCRYPT_COMMUNICATIONS = 0x04;

	/**
	 * Definition of a key flag.  (RFC 2440 5.2.3.21)
	 */
	public static final int ENCRYPT_STORAGE = 0x08;

	/**
	 * Definition of a key flag.  (RFC 2440 5.2.3.21)
	 */
	public static final int PRIVATE_COMPONENT_SPLIT = 0x10;

	/**
	 * Definition of a key flag.  (RFC 2440 5.2.3.21)
	 */
	public static final int MULTI_OWNER_PRIVATE_COMPONENT = 0x80;

	/**
	 * If true, indicates that the key can be used to certify other keys.
	 */
	public boolean certifyOtherKeys = false;

	/**
	 * If true, indicates that the key can be used to sign data.
	 */
	public boolean signData = false;

	/**
	 * If true, indicates that the key can be used to encrypt communications.
	 */
	public boolean encryptCommunications = false;

	/**
	 * If true, indicates that the key can be used to encrypt storage.
	 */
	public boolean encryptStorage = false;

	/**
	 * If true, indicates that the private component of the key may have been
	 * split by a secret sharing mechanism.
	 */
	public boolean privateComponentSplit = false;

	/**
	 * If true, indicates that the private component of the key may be in
	 * the possession of more than one person.
	 */
	public boolean privateComponentInPossessionOfMoreThanOnePerson = false;

	public KeyFlags(byte[] data)
	{
		certifyOtherKeys = ((CERTIFY_OTHER_KEYS | data[0]) == data[0]);
		signData = ((SIGN_DATA | data[0]) == data[0]);
		encryptCommunications = ((ENCRYPT_COMMUNICATIONS | data[0]) == data[0]);
		encryptStorage = ((ENCRYPT_STORAGE | data[0]) == data[0]);
		privateComponentSplit =
			((PRIVATE_COMPONENT_SPLIT | data[0]) == data[0]);
		privateComponentInPossessionOfMoreThanOnePerson =
			((MULTI_OWNER_PRIVATE_COMPONENT | data[0]) == data[0]);
	}

	public KeyFlags()
	{
	}

	public byte[] getBytes()
	{
		byte[] data = new byte[1];
		if (certifyOtherKeys)
			data[0] |= CERTIFY_OTHER_KEYS;
		if (signData)
			data[0] |= SIGN_DATA;
		if (encryptCommunications)
			data[0] |= ENCRYPT_COMMUNICATIONS;
		if (encryptStorage)
			data[0] |= ENCRYPT_STORAGE;
		if (privateComponentSplit)
			data[0] |= PRIVATE_COMPONENT_SPLIT;
		if (privateComponentInPossessionOfMoreThanOnePerson)
			data[0] |= MULTI_OWNER_PRIVATE_COMPONENT;
		return data;
	}
	
	/**
	 * Tests the specified flag to see if it is one of the supported flags
	 * @param flag
	 * @return
	 */
	public static boolean isValid(int flag) {
		return ((flag & CERTIFY_OTHER_KEYS) > 0 || (flag & SIGN_DATA) > 0 || 
				(flag & ENCRYPT_COMMUNICATIONS) > 0 || (flag & ENCRYPT_STORAGE) > 0 || 
				(flag & PRIVATE_COMPONENT_SPLIT) > 0 || (flag & MULTI_OWNER_PRIVATE_COMPONENT) > 0);
	}
}
