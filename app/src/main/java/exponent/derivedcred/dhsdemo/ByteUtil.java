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

package exponent.derivedcred.dhsdemo;

/**
 * General byte handling utilities.
 */
public class ByteUtil
{
	private ByteUtil()
	{
	}

	/**
	 * Concatenates an arbitrary number of byte arrays, returning the result.
	 */
	public static byte[] concatenate(byte[]... byteArrays)
	{
		int resultLength = 0;
		for (byte[] ba : byteArrays)
		{
			resultLength += (null == ba) ? 0 : ba.length;
		}

		byte[] result = new byte[resultLength];

		int idx = 0;
		for (byte[] ba : byteArrays)
		{
			if (ba != null)
			{
				System.arraycopy(ba, 0, result, idx, ba.length);
				idx += ba.length;
			}
		}

		return result;
	}

	/**
	 * Converts a byte to a hex string.
	 */
	public static String toHexString(byte by)
	{
		return String.format("%02X", by & 0xff);
	}

	/**
	 * Converts an array of bytes to a hex string, with no separator between bytes.
	 */
	public static String toHexString(byte[] bytes)
	{
		return toHexString(bytes, null);
	}

	/**
	 * Converts a range of an array of bytes to a hex string, with no separator between bytes.
	 */
	@SuppressWarnings("unused")
	public static String toHexString(byte[] bytes, int start, int end)
	{
		return toHexString(bytes, start, end, null);
	}

	/**
	 * Converts an array of bytes to a hex string, with the specified separator between bytes.
	 */
	public static String toHexString(byte[] bytes, String separator)
	{
		return toHexString(bytes, 0, bytes.length, separator);
	}

	/**
	 * Converts a range of an array of bytes to a hex string, with the specified separator between bytes.
	 */
	public static String toHexString(byte[] bytes, int start, int end, String separator)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = start; i < end; i++)
		{
			if (sb.length() > 0 && null != separator)
			{
				sb.append(' ');
			}
			sb.append(toHexString(bytes[i]));
		}
		return sb.toString();
	}

	/**
	 * Converts a hex string to a byte array.
	 * The string may contain embedded white space.
	 */
	public static byte[] hexStringToByteArray(String s)
	{
		s = s.replaceAll("\\s+", "");
		byte[] data = new byte[s.length() / 2];
		for (int i = 0; i < data.length * 2; i += 2)
		{
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
}
