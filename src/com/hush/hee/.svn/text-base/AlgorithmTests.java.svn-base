/*
 * BEGIN HEADER
 * c 1999-2003 HUSH COMMUNICATIONS CORP      ALL RIGHTS RESERVED
 * This source code is for review only.  Please contact Hush Communications for
 * licensing terms.  (http://corp.hush.com/contact/)
 * END HEADER
 */

/*
 * Created on Sep 5, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package com.hush.hee;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IDEAEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.test.BlockCipherVectorTest;
import org.bouncycastle.crypto.test.DSATest;
import org.bouncycastle.crypto.test.ElGamalTest;
import org.bouncycastle.crypto.test.MD5DigestTest;
import org.bouncycastle.crypto.test.RIPEMD160DigestTest;
import org.bouncycastle.crypto.test.RSATest;
import org.bouncycastle.crypto.test.SHA1DigestTest;
import org.bouncycastle.crypto.test.SHA256DigestTest;
import org.bouncycastle.crypto.test.SHA384DigestTest;
import org.bouncycastle.crypto.test.SHA512DigestTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

import com.hush.hee.legacy.LegacyBlowfishEngine;
import com.hush.util.Conversions;

/**
 * @author bsmith
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
public class AlgorithmTests
{

	public static void runTests() throws RuntimeException
	{
		Test[] tests =
			new Test[] {
				new BlockCipherVectorTest(
					0,
					new AESEngine(),
					new KeyParameter(
						Conversions.hexStringToBytes(
							"80000000000000000000000000000000")),
					"00000000000000000000000000000000",
					"0EDD33D3C621E546455BD8BA1418BEC8"),
				new BlockCipherVectorTest(
					0,
					new LegacyBlowfishEngine(),
					new KeyParameter(
						Conversions.hexStringToBytes("0000000000000000")),
					"0000000000000000",
					"4EF997456198DD78"),
				new BlockCipherVectorTest(
					0,
					new CAST5Engine(),
					new KeyParameter(
						Conversions.hexStringToBytes(
							"0123456712345678234567893456789A")),
					"0123456789ABCDEF",
					"238B4FE5847E44B2"),
				new BlockCipherVectorTest(
					0,
					new DESedeEngine(),
					new KeyParameter(
						Conversions.hexStringToBytes(
							"0123456789abcdef0123456789abcdef")),
					"4e6f77206973207468652074696d6520666f7220616c6c20",
					"3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
				new BlockCipherVectorTest(
					0,
					new IDEAEngine(),
					new KeyParameter(
						Conversions.hexStringToBytes(
							"00112233445566778899AABBCCDDEEFF")),
					"000102030405060708090a0b0c0d0e0f",
					"ed732271a7b39f475b4b2b6719f194bf"),
				new BlockCipherVectorTest(
					0,
					new TwofishEngine(),
					new KeyParameter(
						Conversions.hexStringToBytes(
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")),
					"000102030405060708090A0B0C0D0E0F",
					"8ef0272c42db838bcf7b07af0ec30f38"),
				new SHA1DigestTest(),
				new MD5DigestTest(),
				new RIPEMD160DigestTest(),
				new DSATest(),
				new RSATest(),
				new ElGamalTest(),
				new SHA256DigestTest(),
				new SHA384DigestTest(),
				new SHA512DigestTest()};

		for (int x = 0; x < tests.length; x++)
		{
			TestResult result = tests[x].perform();
			if (!result.isSuccessful())
				throw new RuntimeException("Test failed: " + result.toString());
		}
	}
}
