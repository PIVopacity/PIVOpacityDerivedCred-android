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
import exponent.derivedcred.dhsdemo.Logger;
import exponent.derivedcred.MainActivity;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides constants and utility methods for the Opacity protocol.
 */
public class Opacity
{
	public static final String SELECT = "00 A4 04 00";
	public static final String PIV = "A0 00 00 03 08 00 00 10 00";
	public static final String PIV_LENGTH = "09";
	public static final String SELECT_PIV = SELECT + ' ' + PIV_LENGTH + ' ' + PIV + " 00";
	public static final String CBH = "00";
	public static final String IDH = "00 00 00 00 00 00 00 00";
	public static final String GENERAL_AUTHENTICATE = "00 87 27 04";

	public final static String TAG = "Opacity";
	public final static String PROVIDER = "AndroidOpenSSL";
	public final static String CBC_TRANSFORMATION = "AES/CBC/NoPadding";
	public final static String ECB_TRANSFORMATION = "AES/ECB/NoPadding";

	private final static byte[] LE = {0};

	private enum IvFormat { MESSAGE, RESPONSE }

	public static Logger logger;

	/**
	 * Builds a General Authenticate message.
	 */
	public static byte[] berTlvEncodeLen(int num)
    {
        byte[] msg={};
        if (num<128)
        {
            msg=ByteUtil.hexStringToByteArray(String.format("%02x",num));
        }
        else if (num>127 && num<256)
        {
            msg=ByteUtil.hexStringToByteArray(String.format("81%02x",num));
        }
        else if (num>255 && num<65536)
        {
            msg=ByteUtil.hexStringToByteArray(String.format("82%04x",num));
        }
        else if (num>65535 && num<16777216)
        {
            msg=ByteUtil.hexStringToByteArray(String.format("83%06x",num));
        }
        else if (num>16777215 && num<2147483647)
        {
            msg=ByteUtil.hexStringToByteArray(String.format("84%08x",num));
        }
        return msg;
    }

	public static int berTlvParseLen(byte[] num)
	{
		int mark=(int)num[0]&0xFF;
		switch(mark){
			default:
				return mark;
			case 0x81:
				return (int)num[1] & 0xFF;
			case 0x82:
				return (((int)num[1] & 0xFF)<<8)+((int)num[2] & 0xFF);
			case 0x83:
				return (((int)num[1] & 0xFF)<<16)+(((int)num[2] & 0xFF)<<8)+((int)num[3] & 0xFF);
			case 0x84:
				return (((int)num[1] & 0xFF)<<24)+(((int)num[2] & 0xFF)<<16)+(((int)num[3] & 0xFF)<<8)+((int)num[4] & 0xFF);
		}

	}

	public static int berTlvTagLen(byte b)
	{
		if((b & 0xFF)>127)
		{
			return (b & 0xF)+1;
		} else
		{
			return 1;
		}
	}

	public static byte[] buildGeneralAuthenticate(byte[] opacFlav, byte[] cbh, byte[] idh, byte[] key)
	{
		// Compute length of: chb + idh + key
		byte[] mm = {(byte) (cbh.length + idh.length + key.length)};

		// Compute length of: "81" + mm + cbh + idh + key + "8200"
		byte[] nn = {(byte) (1 + 1 + (mm[0] & 0xff) + 2)};

		// Compute length of: "7C" + nn + "81" + mm + cbh + idh + key + "8200"
		byte[] ll = {(byte) (1 + 1 + (nn[0] & 0xff))};

		return ByteUtil.concatenate(
				ByteUtil.hexStringToByteArray("00 87"),opacFlav,ByteUtil.hexStringToByteArray("04"),
				ll,
				new byte[]{(byte) 0x7c},
				nn,
				new byte[]{(byte) 0x81},
				mm,
				cbh,
				idh,
				key,
				new byte[]{(byte) 0x82},
				LE,
				LE
		);
	}

	/**
	 * Confirms the RMAC in the supplied AES parameters with that in the supplied data.
	 *
	 * @return true is returned if the RMACs compare
	 */
	public static boolean confirmRmac(AesParameters params, byte[] data)
	{
		Cmac cmac = new Cmac(
				params.sessionKeys.get("rmac"),
				ByteUtil.concatenate(params.rmcv, Arrays.copyOfRange(data, 0, data.length - 10)));
		params.rmcv = cmac.mac;

		byte[] rmcvCheck = Arrays.copyOfRange(params.rmcv, 0, 8);
		byte[] dataCheck = Arrays.copyOfRange(data, data.length - 8, data.length);

		logger.newLine();
		logger.info(TAG, "Check Response CMAC:");
		logger.info(TAG, "    " + ByteUtil.toHexString(rmcvCheck, " "));
		logger.info(TAG, "    " + ByteUtil.toHexString(dataCheck, " "));

		return Arrays.equals(rmcvCheck, dataCheck);
	}

	public static boolean confirmCmac(AesParameters params, byte[] data)
	{
		int i=4+berTlvTagLen(data[4]);

		int t=0;
		if((data[i+1+berTlvTagLen(data[i+1])+berTlvParseLen(Arrays.copyOfRange(data,i+1,i+7))] & 0xFF) == 0x97)
		{
			t=3;
		}

		Cmac cmac = new Cmac(
				params.sessionKeys.get("mac"),
				ByteUtil.concatenate(params.mcv,
						Arrays.copyOf(data,4),
						ByteUtil.hexStringToByteArray("800000000000000000000000"),
						Arrays.copyOfRange(data, i, i+berTlvTagLen(data[i+1])+berTlvParseLen(Arrays.copyOfRange(data,i+1,i+6))+t+1)));
		params.mcv = cmac.mac;

		byte[] mcvCheck = Arrays.copyOfRange(params.mcv, 0, 8);
		byte[] dataCheck = Arrays.copyOfRange(data, data.length - 9, data.length-1);

		logger.newLine();
		logger.info(TAG, "Check Command CMAC:");
		logger.info(TAG, "    " + ByteUtil.toHexString(mcvCheck, " "));
		logger.info(TAG, "    " + ByteUtil.toHexString(dataCheck, " "));

		return Arrays.equals(mcvCheck, dataCheck);
	}

	/**
	 * Encrypts APDU.
	 *
	 * @param le may be null or empty
	 * @return the encrypted APDU
	 */
	public static byte[][] encryptApdu(AesParameters params, byte[] ins, byte[] p1, byte[] p2, byte[] message, byte[] le)
			throws GeneralSecurityException
	{
		logger.info(TAG, "ENC Counter: " + String.format("%032X", params.count));

		byte[] msgIv = getIv(params.count, params.ivCipher, IvFormat.MESSAGE);
		logger.info(TAG, "IV: " + ByteUtil.toHexString(msgIv, " "));

		Cipher msgCipher = Cipher.getInstance(CBC_TRANSFORMATION, PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(params.sessionKeys.get("enc"), "AES");
		msgCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(msgIv));

		byte[] encryptedMessage = getEncryptedMessage(message, msgCipher);
		logger.info(TAG, "Encrypted message: " + ByteUtil.toHexString(encryptedMessage, " "));

		Cmac encryptedMessageCmac = getMessageCmac(params, new byte[]{(byte) 0x0c}, ins, p1, p2, encryptedMessage, le);
		params.mcv = encryptedMessageCmac.mac;
		logger.info(TAG, "Encrypted message CMAC and MCV: " + ByteUtil.toHexString(params.mcv, " "));

		byte[] berTlvCmac = ByteUtil.concatenate(ByteUtil.hexStringToByteArray("8E 08"), Arrays.copyOfRange(params.mcv, 0, 8));
		logger.info(TAG, "BER-TLV CMAC: " + ByteUtil.toHexString(berTlvCmac, " "));

		byte[] fullMessage;
		if (null == le || le.length == 0)
		{
			fullMessage = ByteUtil.concatenate(
					encryptedMessage,
					berTlvCmac);
		}
		else
		{
			byte[] berTlvLen = ByteUtil.concatenate(
					ByteUtil.hexStringToByteArray(String.format("97 %02x", le.length)),
					le);
			fullMessage = ByteUtil.concatenate(
					encryptedMessage,
					berTlvLen,
					berTlvCmac);
		}

        byte [][] commandList;
        if (fullMessage.length>255)
        {
            commandList=new byte[1+fullMessage.length/255][];

            for (int i=0; i<fullMessage.length/255; i++)
            {
                commandList[i]=ByteUtil.concatenate(
                        new byte[] { (byte) 0x1c },
                        ins,
                        p1,
                        p2,
                        new byte[] { (byte) 0xFF },
                        Arrays.copyOfRange(fullMessage,i*255,(i+1)*255));
            }

            commandList[fullMessage.length / 255] = ByteUtil.concatenate(
                    new byte[]{(byte) 0x0c},
                    ins,
                    p1,
                    p2,
                    new byte[]{(byte) (fullMessage.length % 255)},
                    Arrays.copyOfRange(fullMessage, fullMessage.length - fullMessage.length % 255, fullMessage.length),
                    new byte[] {(byte) 0x00});
            }
        else
        {
            commandList=new byte[1][];
            commandList[0]=ByteUtil.concatenate(
                    new byte[]{(byte) 0x0c},
                    ins,
                    p1,
                    p2,
                    berTlvEncodeLen(fullMessage.length),
                    fullMessage,
                    new byte[] {(byte) 0x00});
        }

        logger.info(TAG, "Full encryption wrapped APDU: ");
        for(int i=0; i<commandList.length; i++)
        {
            logger.info(TAG, ByteUtil.toHexString(commandList[i], " ") + "\n");
        }
		return commandList;
	}

	/**
	 * Encrypts response messages
	 *
	 *
	 */
	 public static byte[] encryptResponse(AesParameters params, byte[] data, byte[] sw)
			 throws GeneralSecurityException
	 {
		 logger.info(TAG, "ENC Counter: " + String.format("%032X", params.count));

		 byte[] msgIv = getIv(params.count, params.ivCipher, IvFormat.RESPONSE);
		 logger.info(TAG, "IV: " + ByteUtil.toHexString(msgIv, " "));

		 Cipher msgCipher = Cipher.getInstance(CBC_TRANSFORMATION, PROVIDER);
		 SecretKeySpec keySpec = new SecretKeySpec(params.sessionKeys.get("enc"), "AES");
		 msgCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(msgIv));

		 byte[] encryptedResponse={};
		 if(null!=data)
		 {
			 encryptedResponse = getEncryptedMessage(data, msgCipher);
		 }
		 logger.info(TAG, "Encrypted message: " + ByteUtil.toHexString(encryptedResponse, " "));

		 Cmac encryptedResponseCmac = getResponseCmac(params, encryptedResponse, sw);
		 params.rmcv = encryptedResponseCmac.mac;
		 logger.info(TAG, "Encrypted message CMAC and MCV: " + ByteUtil.toHexString(params.rmcv, " "));

		 byte[] berTlvRmac = ByteUtil.concatenate(ByteUtil.hexStringToByteArray("8E 08"), Arrays.copyOfRange(params.rmcv, 0, 8));
		 logger.info(TAG, "BER-TLV CMAC: " + ByteUtil.toHexString(berTlvRmac, " "));

		 return ByteUtil.concatenate(encryptedResponse,
				 new byte[] {(byte) 0x99, (byte) 0x02},
				 sw,
				 berTlvRmac
		 );
	 }

	/**
	 * Decrypts the provided message response.
	 *
	 * @return null if there is no response to decrypt
	 * @throws GeneralSecurityException
	 */
	public static byte[] getDecryptedResponse(AesParameters params, byte[] data)
			throws GeneralSecurityException
	{
		if (data.length < 15)
		{
			return null;
		}

		byte[] msgIv = getIv(params.count, params.ivCipher, IvFormat.RESPONSE);
		//Legacy print for debugging
		//logger.info(TAG, "IV: " + ByteUtil.toHexString(msgIv, " "));

		Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION, PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(params.sessionKeys.get("enc"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(msgIv));

		int i=0;  //0 for response from card
		int t=i+berTlvTagLen(data[i+1])+2;
		//logger.error(TAG,ByteUtil.toHexString(Arrays.copyOfRange(data, t, t+berTlvParseLen(Arrays.copyOfRange(data,i+1,i+6))-1)," "));
		return cipher.doFinal(Arrays.copyOfRange(data, t, t+berTlvParseLen(Arrays.copyOfRange(data,i+1,i+6))-1));
	}

	public static byte[] getDecryptedCommand(AesParameters params, byte[] data)
			throws GeneralSecurityException
	{
		byte[] msgIv = getIv(params.count, params.ivCipher, IvFormat.MESSAGE);

		Cipher cipher = Cipher.getInstance(CBC_TRANSFORMATION, PROVIDER);
		SecretKeySpec keySpec = new SecretKeySpec(params.sessionKeys.get("enc"), "AES");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(msgIv));

		int i=4+berTlvTagLen(data[4]);
		int t=i+berTlvTagLen(data[i+1])+2;
		return cipher.doFinal(Arrays.copyOfRange(data, t, t+berTlvParseLen(Arrays.copyOfRange(data,i+1,i+6))-1));
	}

	private static byte[] getEncryptedMessage(byte[] message, Cipher cipher)
			throws GeneralSecurityException
	{
		byte[] paddedMessage = pad(message, cipher);
		logger.info(TAG, "Padded message: " + ByteUtil.toHexString(paddedMessage, " "));

		byte[] encryptedMessage = cipher.doFinal(paddedMessage);
		byte[] header = ByteUtil.hexStringToByteArray(String.format("87"));
        byte[] headerLen= berTlvEncodeLen(encryptedMessage.length + 1);
        byte[] headerTail = ByteUtil.hexStringToByteArray(String.format("01"));
		return ByteUtil.concatenate(header, headerLen, headerTail, encryptedMessage);
	}

	private static byte[] getIv(int count, Cipher cipher, IvFormat format)
			throws GeneralSecurityException
	{
		byte[] data = IvFormat.MESSAGE == format
				? ByteUtil.hexStringToByteArray(String.format("%032X", count))
				: ByteUtil.hexStringToByteArray(String.format("80 %030X", count));
		return cipher.doFinal(data);
	}

	private static Cmac getMessageCmac(AesParameters params, byte[] cla, byte[] ins, byte[] p1, byte[] p2, byte[] enc, byte[] le)
	{
		byte[] message;
		if (null == le || 0 == le.length)
		{
			message = ByteUtil.concatenate(
					params.mcv,
					new byte[] { (byte)0x0c },
					ins,
					p1,
					p2,
					new byte[] { (byte)0x80 },
					new byte[11],
					enc);
		}
		else
		{
			message = ByteUtil.concatenate(
					params.mcv,
					cla,
					ins,
					p1,
					p2,
					new byte[] { (byte)0x80 },
					new byte[11],
					enc,
					ByteUtil.hexStringToByteArray(String.format("97 %02x", le.length)),
					le);
		}

		return new Cmac(params.sessionKeys.get("mac"), message);
	}

	private static Cmac getResponseCmac(AesParameters params, byte[] data, byte[] sw)
	{
		byte [] message = ByteUtil.concatenate(
				params.rmcv,
				data,
				new byte[] {(byte) 0x99, (byte) 0x02},
				sw
		);

		return new Cmac(params.sessionKeys.get("rmac"),message);
	}

	/**
	 * KDF function defined in NIST 800-56A 5.8.1
	 *
	 * @param z         shared secret key
	 * @param length    length of number of bits of derived keying material (512 for NIST 800-73-4 4.1.6)
	 * @param otherInfo construction of byte string defined in NIST 800-73-4 4.1.6
	 */
	public static byte[] kdf(byte[] z, int length, byte[] otherInfo, String hashFunc)
	{
		MessageDigest digest;
		try
		{
			digest = MessageDigest.getInstance(hashFunc);
		}
		catch (Exception e)
		{
			MainActivity.logger.error(TAG, "Unable to create digest", e);
			return null;
		}

		// Omitted: Source data and derived keying material length checks

		int hashLength = digest.getDigestLength()*8;
		int reps = (int) Math.ceil((double) length / (double) hashLength);
		byte[] output = null;
		for (int i = 1; i < reps; i++)
		{
			digest.update(ByteUtil.hexStringToByteArray(String.format("%08X", i)));
			digest.update(z);
			output = ByteUtil.concatenate(output, digest.digest(otherInfo));
			digest.reset();
		}

		digest.update(ByteUtil.hexStringToByteArray(String.format("%08X", reps)));
		digest.update(z);
		byte[] b = digest.digest(otherInfo);
		if (length % hashLength != 0)
		{
			b = Arrays.copyOfRange(b, 0, (length % hashLength) / 8);
		}
		output = ByteUtil.concatenate(output, b);

		return output;
	}

	/**
	 * Builds formatted dictionary for secret keys from derived keying material from KDF
	 *
	 * @param keyingMaterial map of keying material
	 * @return a map with keys "cfrm", "mac", "enc", "rmac"
	 */
	public static HashMap<String, byte[]> kdfToDict(byte[] keyingMaterial)
	{
		int keyLen=keyingMaterial.length/4;

		HashMap<String, byte[]> result = new HashMap<>();
		result.put("cfrm", Arrays.copyOfRange(keyingMaterial, 0*keyLen, 1*keyLen));
		result.put("mac", Arrays.copyOfRange(keyingMaterial, 1*keyLen, 2*keyLen));
		result.put("enc", Arrays.copyOfRange(keyingMaterial, 2*keyLen, 3*keyLen));
		result.put("rmac", Arrays.copyOfRange(keyingMaterial, 3*keyLen, 4*keyLen));

		return result;
	}

	/**
	 * Pads the provided byte array according to the block size of the provided cipher.
	 *
	 * @return the padded byte array
	 */
	private static byte[] pad(byte[] s, Cipher cipher)
	{
		// Padding as defined by NIST SP800-73-4 Part 2 Page 32
		int padLength = (s.length + 1) % cipher.getBlockSize();
		padLength = 0 == padLength ? 0 : cipher.getBlockSize() - padLength;
		byte[] pad = new byte[padLength];
		return ByteUtil.concatenate(s, new byte[] { (byte)0x80 }, pad);
	}


    /**
     * PCKS #1 v1.5 padding defined in IETF RFC 2313
     * @param BT Block Type Byte, shall be '01' or '00' for private key operation
     * @param Nonce Nonce used for RSA signing challenge
     * @return padded message
     */
    public static byte[] pkcs1v15Pad(String BT, String Nonce, int bits)
    {
        return pkcs1v15Pad(BT,Nonce.getBytes(), bits);
    }

    public static byte[] pkcs1v15Pad(String BT, byte[] Nonce, int bits)
    {
        byte[] msg=new byte[] { (byte) 0x00 };
        msg = ByteUtil.concatenate(msg, ByteUtil.hexStringToByteArray(BT));
        for(int i =0; i<((bits/8)-3-Nonce.length); i++)
        {
            msg = ByteUtil.concatenate(msg, new byte[] { (byte) 0xFF});
        }
        msg = ByteUtil.concatenate(msg, new byte[] { (byte) 0x00 });
        msg = ByteUtil.concatenate(msg, Nonce);
        return msg;
    }

	public static String getAesType(byte b)
	{
		if((b & 0xFF)==0x2E)
		{
			return "AES-256";
		} else if((b & 0xFF)==0x27)
		{
			return "AES-128";
		}else
		{
			return null;
		}
	}
}
