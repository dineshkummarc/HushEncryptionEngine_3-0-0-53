/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

/*
 * Class representing a key record.
 * 
 */

package com.hush.hee;

import java.io.Serializable;

import com.hush.hee.keyserver.GeneratedPassword;
import com.hush.pgp.Keyring;

public class KeyRecord implements Serializable
{
	private static final long serialVersionUID = -2342592569651242437L;

	public long timestamp;

	/**
	 * The private keyring, retrieved by a private key lookup.
	 */
	public Keyring privateKeyring = new Keyring();

	/**
	 * The public keyring, retrieved by a public key lookup
	 */
	public Keyring publicKeyring = new Keyring();

	/**
	 * The public keyring, retrieved by a public key lookup
	 */
	public Keyring adkKeyring = new Keyring();
	
	/**
	 * The alias.
	 */
	public String alias;

	/**
	 * The private alias.
	 */
	public String privateAlias;

	/**
	 * Whether or not a shared secret is associated with this key.
	 */
	public boolean sharedSecret;

	/**
	 * The iteration count for generating the private alias
	 */
	public int privateAliasIterationCount;
	
	/**
	 * The hash for generating the private alias
	 */
	public int privateAliasHash;
	
	/**
	 * Encryption method specifying that this key should not
	 * be used for encryption
	 */
	public static final String NONE = "None";

	/**
	 * Encryption method specifying that this key should be
	 * used for Hushmail Express style encryption (the user
	 * does not have encryption software)
	 */
	public static final String WEB = "Web";
	
	/**
	 * Encryption method specifying that this key should
	 * be used for regular encryption.
	 */
	public static final String NORMAL = "Normal";
	
	/**
	 * The encryption method to be used with this public key.
	 */
	public String encryptionMethod;
	
	/**
	 * The GeneratedPassword object for this alias.  May or may
	 * not be present.
	 */
	public GeneratedPassword generatedPassword;
	
	/**
	 * Creates a new instance of KeyRecord, and sets the time stamp to now.
	 */
	public KeyRecord()
	{
		this.timestamp = System.currentTimeMillis();
		privateKeyring.setVerifySelfSignatures(false);
	}

	public long lastAccessTime;
}