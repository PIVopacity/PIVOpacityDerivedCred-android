/*
Copyright (c) 2017 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Written by Christopher Williams, Ph.D. (cwilliams@exponent.com)
*/

package exponent.derivedcred.opacity;

import exponent.derivedcred.dhsdemo.ByteUtil;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.macs.CMac;
import org.spongycastle.crypto.params.KeyParameter;

import java.util.Arrays;

/**
 * Support for generating amd verifying CMACs.
 *
 *
 */
public class Cmac
{
	public byte[] key;
	public byte[] message;
	public byte[] mac;
	public String error;

    /**
     * Checks the CMAC implementation against NIST test data. NIST SP 800-38B Appendix D.1 (p.15)
     */
	public final static String NIST_TEST_KEY = "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c";
	public final static String NIST_TEST_MESSAGE = "";
	public final static String NIST_TEST_MAC = "bb 1d 69 29 e9 59 37 28 7f a3 7d 12 9b 75 67 46";

	/**
	 * Creates a new instance using the given key and message.
	 */

    public Cmac(byte[] key, byte[] message)
	{
		this.key = Arrays.copyOf(key, key.length);
		this.message = Arrays.copyOf(message, message.length);

        CMac cmac = new CMac(new AESEngine());
        cmac.init(new KeyParameter(key));
        cmac.update(message,0,message.length);
        this.mac=new byte[16];
        cmac.doFinal(mac,0);
	}

	public static boolean nistCheck()
	{
		Cmac cmac = new Cmac(ByteUtil.hexStringToByteArray(NIST_TEST_KEY), ByteUtil.hexStringToByteArray(NIST_TEST_MESSAGE));
		return (null == cmac.error && cmac.verify(ByteUtil.hexStringToByteArray(NIST_TEST_MAC)));
	}

	/**
	 * Verifies generated MAC against provided expected MAC.
	 * @return true if the two MACs are the same
	 */
	public boolean verify(byte[] expectedMac)
	{
		return Arrays.equals(mac, expectedMac);
	}


}
