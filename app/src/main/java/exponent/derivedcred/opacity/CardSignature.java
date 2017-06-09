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

import exponent.derivedcred.MainActivity;
import exponent.derivedcred.dhsdemo.ByteUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This is the result of parsing the response to a GENERAL_AUTHENTICATE command.
 */
public class CardSignature
{
	public final byte[] cb;
	public final byte[] nonce;
	public final byte[] cryptogram;
	public final byte[] issuerId;
	public final byte[] guid;
	public final byte[] algorithmOID;
	public final byte[] publicKey;
	public final byte[] cvc;
	public final byte[] message;
	public final byte[] id;

	/**
	 * Create a new instance with the given properties.
	 */
	public CardSignature(byte[] cb, byte[] nonce, byte[] cryptogram, byte[] issuerId,
						 byte[] guid, byte[] algorithmOID, byte[] publicKey, byte[] cvc,
						 byte[] message, byte[] id)
	{
		this.cb = cb;
		this.nonce = nonce;
		this.cryptogram = cryptogram;
		this.issuerId = issuerId;
		this.guid = guid;
		this.algorithmOID = algorithmOID;
		this.publicKey = publicKey;
		this.cvc = cvc;
		this.message = message;
		this.id = id;
	}

	/**
	 * Returns a new instance created by parsing the given message.
	 */
	public static CardSignature parse(byte[] data)
	{
		int start = 6;
		int end = start + 1;
		byte[] cb = Arrays.copyOfRange(data, start, end);

		start = end;
		end = start + 16;
		byte[] nonce = Arrays.copyOfRange(data, start, end);

		start = end;
		end = start + 16;
		byte[] cryptogram = Arrays.copyOfRange(data, start, end);

		start = end;
		byte[] id;
		try
		{
			MessageDigest md = MessageDigest.getInstance("sha256");
			byte[] digest = md.digest(Arrays.copyOfRange(data, start, data.length));
			id = Arrays.copyOfRange(digest, 0, 8);
		}
		catch (NoSuchAlgorithmException e)
		{
			MainActivity.logger.error(Opacity.TAG, "Unable to create sha256 digest", e);
			id = new byte[8];
		}

		//start = end + 8;
		start = ByteUtil.toHexString(data).toLowerCase().indexOf("5f290180")/2+6; // Modified to make code agnostic to inconsistencies of NIST SP 800-73-4 Part 2, 4.1.5, Table 15 BER-TLV Formatting
		end = start + (data[start - 1] & 0xff);
		byte[] issuerId = Arrays.copyOfRange(data, start, end);

		start = end + 3;
		end = start + (data[start - 1] & 0xff);
		byte[] guid = Arrays.copyOfRange(data, start, end);

		start = end + 5;
		end = start + (data[start - 1] & 0xff);
		byte[] algorithmOID = Arrays.copyOfRange(data, start, end);

		start = end + 2;
		end = start + (data[start - 1] & 0xff);
		byte[] publicKey = Arrays.copyOfRange(data, start, end);

		start = end + 7;
		end = start + (data[start - 1] & 0xff);
		byte[] cvc = Arrays.copyOfRange(data, start, end);

		byte[] message = Arrays.copyOfRange(data, 6 + 1 + 16 + 16 + 2, start - 3);

		return new CardSignature(cb, nonce, cryptogram, issuerId, guid, algorithmOID, publicKey, cvc, message, id);
	}

	public static CardSignature parse192(byte[] data)
	{
		int start = 8;
		int end = start + 1;
		byte[] cb = Arrays.copyOfRange(data, start, end);

		start = end;
		end = start + 24;
		byte[] nonce = Arrays.copyOfRange(data, start, end);

		start = end;
		end = start + 16;
		byte[] cryptogram = Arrays.copyOfRange(data, start, end);

		start = end;
		byte[] id;
		try
		{
			MessageDigest md = MessageDigest.getInstance("sha256");
			byte[] digest = md.digest(Arrays.copyOfRange(data, start, data.length));
			id = Arrays.copyOfRange(digest, 0, 8);
		}
		catch (NoSuchAlgorithmException e)
		{
			MainActivity.logger.error(Opacity.TAG, "Unable to create sha256 digest", e);
			id = new byte[8];
		}

		//start = end + 8;
		start = ByteUtil.toHexString(data).toLowerCase().indexOf("5f290180")/2+6; // Modified to make code agnostic to interpretations of NIST SP 800-73-4 Part 2, 4.1.5 Table 15
		end = start + (data[start - 1] & 0xff);
		byte[] issuerId = Arrays.copyOfRange(data, start, end);

		start = end + 3;
		end = start + (data[start - 1] & 0xff);
		byte[] guid = Arrays.copyOfRange(data, start, end);

		start = end + 5;
		end = start + (data[start - 1] & 0xff);
		byte[] algorithmOID = Arrays.copyOfRange(data, start, end);

		start = end + 2;
		end = start + (data[start - 1] & 0xff);
		byte[] publicKey = Arrays.copyOfRange(data, start, end);

		start = end + 7;
		end = start + (data[start - 1] & 0xff);
		byte[] cvc = Arrays.copyOfRange(data, start, end);

		byte[] message = Arrays.copyOfRange(data, 8 + 1 + 24 + 16 + 2, start - 3);

		return new CardSignature(cb, nonce, cryptogram, issuerId, guid, algorithmOID, publicKey, cvc, message, id);
	}
}
