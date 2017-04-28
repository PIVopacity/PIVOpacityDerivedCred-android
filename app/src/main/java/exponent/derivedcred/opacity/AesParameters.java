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

import java.security.GeneralSecurityException;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Parameters for AES operations.
 */
public class AesParameters
{
	public int count;
	public byte[] mcv;
	public byte[] rmcv;
	public HashMap<String, byte[]> sessionKeys;
	public Cipher ivCipher;

	public AesParameters(int count, byte[] mcv, byte[] rmcv, HashMap<String, byte[]> sessionKeys)
			throws GeneralSecurityException
	{
		this.count = count;
		this.mcv = mcv;
		this.rmcv = rmcv;
		this.sessionKeys = sessionKeys;

		ivCipher = Cipher.getInstance(Opacity.ECB_TRANSFORMATION, Opacity.PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(sessionKeys.get("enc"), "AES");
		ivCipher.init(Cipher.ENCRYPT_MODE, keySpec);
	}
}
