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
import exponent.derivedcred.dhsdemo.Logger;
import exponent.derivedcred.dhsdemo.Transceiver;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import javax.crypto.KeyAgreement;


/**
 * Holds the code for opening a secure tunnel for the Opacity protocol.
 */
public class OpacitySecureTunnel
{
	private Logger logger;

	private final static String TAG = "OpacitySecureTunnel";

	private final static String ERROR_TITLE = "Error";

	private final static String CARD_COMM_ERROR = "Error communicating with card: check log for details.";
	private final static String CARD_RESP_ERROR = "Unexpected response from card: check log for details.";
	private final static String CRYPTO_ERROR = "Cryptography error: check log for details.";

	public Integer TunnelCreationTimer;
	public CardSignature cardSignature;

	public OpacitySecureTunnel(Logger logger)
	{
		this.logger = logger;
	}

	public Integer getCreationTime()
	{
		if(TunnelCreationTimer==null)
		{
			return null;
		}
		else
		{
			return TunnelCreationTimer;
		}
	}

	/**
	 * Opens the secure tunnel using the supplied transceiver.
	 *
	 * @param transceiver the mechanism for communicating with the card
	 * @return the session keys (cfrm, mac, enc, rmac) for the secure tunnel
	 * @throws GeneralSecurityException
	 */
	public HashMap<String, byte[]> openTunnel(Transceiver transceiver,byte opacFlav)
			throws GeneralSecurityException
	{
		long startTime = System.currentTimeMillis();

		ECGenParameterSpec ecSpec;
		if((opacFlav & 0xFF)==0x2E)
		{
			ecSpec = new ECGenParameterSpec("secp384r1");
		} else if((opacFlav & 0xFF)==0x27)
		{
			ecSpec = new ECGenParameterSpec("prime256v1");
		} else
		{
			logger.error(TAG,"Unrecognized Secure Message Parameter");
			return null;
		}



		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(ecSpec, new SecureRandom());
        KeyPair pair = kpg.generateKeyPair();
        ECPrivateKey ecPriv = (ECPrivateKey) pair.getPrivate();
        ECPublicKey ecPub = (ECPublicKey) pair.getPublic();

        byte[] hostPublicKey;
		if((opacFlav & 0xFF)==0x2E)
		{
			hostPublicKey = Arrays.copyOfRange(ecPub.getEncoded(),ecPub.getEncoded().length-97,ecPub.getEncoded().length);
		} else if((opacFlav & 0xFF)==0x27)
		{
			hostPublicKey = Arrays.copyOfRange(ecPub.getEncoded(),ecPub.getEncoded().length-65,ecPub.getEncoded().length);
		}else
		{
			logger.error(TAG,"Unrecognized Secure Message Parameter");
			return null;
		}

		logger.newLine();
		logger.info(TAG, "Host Generated "+ecSpec.getName()+" Ephemeral Pubic Key: " + ByteUtil.toHexString(hostPublicKey, " "));


		Transceiver.Response response = transceiver.transceive("GENERAL AUTHENTICATE",
				Opacity.buildGeneralAuthenticate(new byte[] {opacFlav},
						ByteUtil.hexStringToByteArray(Opacity.CBH),
						ByteUtil.hexStringToByteArray(Opacity.IDH),
						hostPublicKey
				));
		if (null == response)
		{
			logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		if((opacFlav & 0xFF)==0x2E)
		{
			cardSignature = CardSignature.parse192(response.data);
		} else if((opacFlav & 0xFF)==0x27)
		{
			cardSignature = CardSignature.parse(response.data);
		}


		logger.newLine();
		logger.info(TAG, "CBicc: " + ByteUtil.toHexString(cardSignature.cb, " "));

		logger.newLine();
		logger.info(TAG, "Nicc: " + ByteUtil.toHexString(cardSignature.nonce, " "));

		logger.newLine();
		logger.info(TAG, "AuthCryptogram: " + ByteUtil.toHexString(cardSignature.cryptogram, " "));

		logger.newLine();
		logger.info(TAG, "Sig ID: " + ByteUtil.toHexString(cardSignature.id, " "));

		logger.newLine();
		logger.info(TAG, "Issuer ID: " + ByteUtil.toHexString(cardSignature.issuerId, " "));

		logger.newLine();
		logger.info(TAG, "GUID: " + ByteUtil.toHexString(cardSignature.guid, " "));

		if((opacFlav & 0xFF)==0x2E)
		{
			logger.newLine();
			logger.info(TAG, "Algorithm OID (2B:81:04:00:22 for ECDH, P-384): " + ByteUtil.toHexString(cardSignature.algorithmOID, " "));
		} else if((opacFlav & 0xFF)==0x27)
		{
			logger.newLine();
			logger.info(TAG, "Algorithm OID (2A:86:48:CE:3D:03:01:07 for ECDH, P-256): " + ByteUtil.toHexString(cardSignature.algorithmOID, " "));
		}

		logger.newLine();
		logger.info(TAG, "Public Key: " + ByteUtil.toHexString(cardSignature.publicKey, " "));

		logger.newLine();
		logger.info(TAG, "Digital Signature (CVC): " + ByteUtil.toHexString(cardSignature.cvc, " "));

		logger.newLine();
		if (0 != cardSignature.cb[0])
		{
			logger.error(TAG, "[H4] Persistent binding enabled, Terminating Session");
			logger.alert(CARD_RESP_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		logger.info(TAG, "[H4] Persistent binding disabled");


        KeyFactory kf=KeyFactory.getInstance("EC");
		ECPublicKeySpec keySpec = null;
		if((opacFlav & 0xFF)==0x2E)
		{
			keySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(ByteUtil.toHexString(cardSignature.publicKey,1,49),16), new BigInteger(ByteUtil.toHexString(cardSignature.publicKey,49,97),16)),ecPub.getParams());
		} else if((opacFlav & 0xFF)==0x27)
		{
			keySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(ByteUtil.toHexString(cardSignature.publicKey,1,33),16), new BigInteger(ByteUtil.toHexString(cardSignature.publicKey,33,65),16)),ecPub.getParams());
		}
        ECPublicKey cardPubKey= (ECPublicKey) kf.generatePublic(keySpec);
        logger.info(TAG,"Card Public Key: "+ByteUtil.toHexString(cardPubKey.getEncoded()));

		KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
        keyAgree.init(ecPriv);
        keyAgree.doPhase(cardPubKey,true);
        byte[] z = keyAgree.generateSecret();


		logger.newLine();
		logger.info(TAG, "[H8] Compute ECDH Shared Secret Z using OpenSSL : " + ByteUtil.toHexString(z, " "));

		logger.newLine();

		String otherInfo=null;
		if((opacFlav & 0xFF)==0x2E)
		{
			logger.info(TAG, "[H10] Compute session keys using Cipher Suite 7 from NIST 800-73-4 4.1.6");
			otherInfo=
					"04 0D 0D 0D 0D 08 " +
							Opacity.IDH +
							" 01 " +
							Opacity.CBH +
							" 10 " +
							ByteUtil.toHexString(hostPublicKey, 1, 17, " ") +
							" 08 " +
							ByteUtil.toHexString(cardSignature.id, " ") +
							" 18 " +
							ByteUtil.toHexString(cardSignature.nonce, " ") +
							" 01 " +
							ByteUtil.toHexString(cardSignature.cb, " ");
		} else if((opacFlav & 0xFF)==0x27)
		{
			logger.info(TAG, "[H10] Compute session keys using Cipher Suite 2 from NIST 800-73-4 4.1.6");
			otherInfo =
					"04 09 09 09 09 08 " +
							Opacity.IDH +
							" 01 " +
							Opacity.CBH +
							" 10 " +
							ByteUtil.toHexString(hostPublicKey, 1, 17, " ") +
							" 08 " +
							ByteUtil.toHexString(cardSignature.id, " ") +
							" 10 " +
							ByteUtil.toHexString(cardSignature.nonce, " ") +
							" 01 " +
							ByteUtil.toHexString(cardSignature.cb, " ");
		}




		//Print otherInfo for debugging
		//logger.info(TAG, "otherInfo = " + otherInfo);
		byte[] kdf=new byte[0];
		if((opacFlav & 0xFF)==0x2E)
		{
			kdf = Opacity.kdf(z, 1024, ByteUtil.hexStringToByteArray(otherInfo),"sha384");
		} else if((opacFlav & 0xFF)==0x27)
		{
			kdf = Opacity.kdf(z, 512, ByteUtil.hexStringToByteArray(otherInfo),"sha256");
		}

		//logger.info(TAG, "kdf = " + ByteUtil.toHexString(kdf, " "));
		HashMap<String, byte[]> sessionKeys = Opacity.kdfToDict(kdf);

		logger.newLine();
		logger.info(TAG, "Session keys:");
		logger.info(TAG, "    CFRM: " + ByteUtil.toHexString(sessionKeys.get("cfrm"), " "));
		logger.info(TAG, "    MAC: " + ByteUtil.toHexString(sessionKeys.get("mac"), " "));
		logger.info(TAG, "    ENC: " + ByteUtil.toHexString(sessionKeys.get("enc"), " "));
		logger.info(TAG, "    RMAC: " + ByteUtil.toHexString(sessionKeys.get("rmac"), " "));


        /*// Test CMAC implementation for NIST compliance:
		if (!Cmac.nistCheck())
		{
            logger.error(TAG, "CMAC NIST test failed");
	        logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return null;
        }*/


		logger.newLine();
		logger.info(TAG, "[H12]  Check AuthCryptogram (CMAC with AES-128 cipher, NIST 800-73-4 4.1.7)");

		// Verify CMAC of card signature:
		byte[] message = ByteUtil.concatenate(
				ByteUtil.hexStringToByteArray("4B 43 5F 31 5F 56"),
				cardSignature.id,
				ByteUtil.hexStringToByteArray(Opacity.IDH),
				Arrays.copyOfRange(hostPublicKey, 1, hostPublicKey.length)
		);
		Cmac check = new Cmac(sessionKeys.get("cfrm"), message);
		if (check.error != null)
		{
			logger.error(TAG, "Error generating CMAC for card Auth Cryptogram: " + check.error);
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		logger.info(TAG, "    " + ByteUtil.toHexString(check.mac, " "));
		logger.info(TAG, "    " + ByteUtil.toHexString(cardSignature.cryptogram, " "));

		if (!check.verify(cardSignature.cryptogram))
		{
			logger.error(TAG, "Error verifying CMAC of card Auth Cryptogram");
			logger.alert(CRYPTO_ERROR, ERROR_TITLE);
			transceiver.close();
			return null;
		}

		long stopTime = System.currentTimeMillis();
		TunnelCreationTimer=(int)(stopTime - startTime);
		logger.newLine();
		logger.info(TAG, "Opacity Session Established in " + TunnelCreationTimer.toString() + " ms");
		logger.newLine();

		return sessionKeys;
	}


	/**
	 * Opens the secure tunnel on client side.
	 *
	 * @param  requestAPDU Authenticate APDU from host, HashMap for session keys
	 * @return General Authenticate response to be sent to the host
	 * @throws GeneralSecurityException
	 */
	public HashMap<String,byte[]> openClientTunnel(byte[] requestAPDU)
			throws GeneralSecurityException
	{
		long startTime = System.currentTimeMillis();

		if (requestAPDU[9]!=0)
		{
			long stopTime = System.currentTimeMillis();
			TunnelCreationTimer=(int)(stopTime - startTime);
			return null;
		} else
		{
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime256v1");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			kpg.initialize(ecSpec, new SecureRandom());
			KeyPair pair = kpg.generateKeyPair();
			ECPrivateKey ecPriv = (ECPrivateKey) pair.getPrivate();
			ECPublicKey ecPub = (ECPublicKey) pair.getPublic();

			byte[] clientPublicKey = Arrays.copyOfRange(ecPub.getEncoded(), ecPub.getEncoded().length - 65, ecPub.getEncoded().length);

			logger.newLine();
			logger.info(TAG, "Client Generated prime256v1 Ephemeral Pubic Key: " + ByteUtil.toHexString(clientPublicKey, " "));

			//Get host public key from requestAPDU
			KeyFactory kf=KeyFactory.getInstance("EC");
			ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(ByteUtil.toHexString(requestAPDU,19,51),16), new BigInteger(ByteUtil.toHexString(requestAPDU,51,83),16)),ecPub.getParams());
			ECPublicKey hostPubKey= (ECPublicKey) kf.generatePublic(keySpec);
			logger.info(TAG,"Host Public Key: "+ByteUtil.toHexString(hostPubKey.getEncoded()," "));

			KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
			keyAgree.init(ecPriv);
			keyAgree.doPhase(hostPubKey,true);
			byte[] z = keyAgree.generateSecret();

			byte[] CBicc = new byte[]{0x00};

			byte[] Nicc = new byte[16];
			SecureRandom rand = new SecureRandom();
			rand.nextBytes(Nicc);

			MessageDigest digest;
			try
			{
				digest = MessageDigest.getInstance("sha256");
			}
			catch (Exception e)
			{
				MainActivity.logger.error(TAG, "Unable to create sha256 digest", e);
				return null;
			}


			//Create CVC:
			byte[] Cicc=ByteUtil.concatenate(
					ByteUtil.hexStringToByteArray("7F 21 5F 29 01 80 42 08"),
					ByteUtil.hexStringToByteArray("01 01 01 01 01 01 01 01"), //Issuer ID
					ByteUtil.hexStringToByteArray("5F 20 10"),
					ByteUtil.hexStringToByteArray("30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30"), //GUID
					ByteUtil.hexStringToByteArray("7F 49 4D 06 08"),
					ByteUtil.hexStringToByteArray("2A 86 48 CE 3D 03 01 07"), //Algorithm OID for ECDH P-256
					ByteUtil.hexStringToByteArray("86 "+String.format("%02X",clientPublicKey.length)),
					clientPublicKey,
					ByteUtil.hexStringToByteArray("5F 4C 01 00")
			);

			Signature cvcSigner= Signature.getInstance("ECDSA");
			cvcSigner.initSign(ecPriv,new SecureRandom());
			cvcSigner.update(Cicc);
			byte[] cvcSig=cvcSigner.sign();

			Cicc=ByteUtil.concatenate(Cicc,
					ByteUtil.hexStringToByteArray("5F 37"),
					Opacity.berTlvEncodeLen(cvcSig.length),
					cvcSig);

			byte[] IDicc=Arrays.copyOf(digest.digest(Cicc),8);


			String IDh=ByteUtil.toHexString(requestAPDU,10,18," ");

			String otherInfo =
					"04 09 09 09 09 08 " +
							IDh +
							" 01 " +
							" 00 " + //CBh
							" 10 " +
							ByteUtil.toHexString(hostPubKey.getEncoded(), 27, 43, " ") +
							" 08 " +
							ByteUtil.toHexString(IDicc, " ") +
							" 10 " +
							ByteUtil.toHexString(Nicc, " ") +
							" 01 " +
							ByteUtil.toHexString(CBicc, " ");

			HashMap<String,byte[]> sessionKeys;

			byte[] kdf = Opacity.kdf(z, 512, ByteUtil.hexStringToByteArray(otherInfo),"sha256");
			//logger.info(TAG, "kdf = " + ByteUtil.toHexString(kdf, " "));
			sessionKeys = Opacity.kdfToDict(kdf);

			z=new byte[]  {0x00};

			logger.newLine();
			logger.info(TAG, "Session keys:");
			logger.info(TAG, "    CFRM: " + ByteUtil.toHexString(sessionKeys.get("cfrm"), " "));
			logger.info(TAG, "    MAC: " + ByteUtil.toHexString(sessionKeys.get("mac"), " "));
			logger.info(TAG, "    ENC: " + ByteUtil.toHexString(sessionKeys.get("enc"), " "));
			logger.info(TAG, "    RMAC: " + ByteUtil.toHexString(sessionKeys.get("rmac"), " "));

			// Create AuthCryptogramicc:
			byte[] message = ByteUtil.concatenate(
					ByteUtil.hexStringToByteArray("4B 43 5F 31 5F 56"), //"KC_1_V"
					IDicc,
					ByteUtil.hexStringToByteArray(IDh),
					Arrays.copyOfRange(hostPubKey.getEncoded(), 27,hostPubKey.getEncoded().length)
			);

			byte[] AuthCryptogramicc = new Cmac(sessionKeys.get("cfrm"), message).mac;

			sessionKeys.put("cfrm",new byte[] {0x00});


			long stopTime = System.currentTimeMillis();
			TunnelCreationTimer = (int) (stopTime - startTime);

			logger.newLine();
			logger.info(TAG, "Opacity Session Established in " + TunnelCreationTimer.toString() + " ms on client side");
			logger.newLine();

			byte[] payload=ByteUtil.concatenate(Opacity.berTlvEncodeLen(ByteUtil.concatenate(CBicc,Nicc,AuthCryptogramicc,Cicc).length),CBicc,Nicc,AuthCryptogramicc,Cicc);


			sessionKeys.put("pub",ByteUtil.concatenate(ByteUtil.hexStringToByteArray("7C"),
					Opacity.berTlvEncodeLen(payload.length+1),
					ByteUtil.hexStringToByteArray("82"),payload));

			return sessionKeys;
		}
	}

	public HashMap<String,byte[]> openClientTunnel192(byte[] requestAPDU)
			throws GeneralSecurityException
	{
		long startTime = System.currentTimeMillis();

		if (requestAPDU[9]!=0)
		{
			long stopTime = System.currentTimeMillis();
			TunnelCreationTimer=(int)(stopTime - startTime);
			return null;
		} else
		{
			ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			kpg.initialize(ecSpec, new SecureRandom());
			KeyPair pair = kpg.generateKeyPair();
			ECPrivateKey ecPriv = (ECPrivateKey) pair.getPrivate();
			ECPublicKey ecPub = (ECPublicKey) pair.getPublic();

			byte[] clientPublicKey = Arrays.copyOfRange(ecPub.getEncoded(), ecPub.getEncoded().length - 97, ecPub.getEncoded().length);

			logger.newLine();
			logger.info(TAG, "Client Generated prime256v1 Ephemeral Pubic Key: " + ByteUtil.toHexString(clientPublicKey, " "));

			//Get host public key from requestAPDU
			KeyFactory kf=KeyFactory.getInstance("EC");
			ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(ByteUtil.toHexString(requestAPDU,19,67),16), new BigInteger(ByteUtil.toHexString(requestAPDU,67,115),16)),ecPub.getParams());
			ECPublicKey hostPubKey= (ECPublicKey) kf.generatePublic(keySpec);
			logger.info(TAG,"Host Public Key: "+ByteUtil.toHexString(hostPubKey.getEncoded()," "));

			KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
			keyAgree.init(ecPriv);
			keyAgree.doPhase(hostPubKey,true);
			byte[] z = keyAgree.generateSecret();

			byte[] CBicc = new byte[]{0x00};

			byte[] Nicc = new byte[24];
			SecureRandom rand = new SecureRandom();
			rand.nextBytes(Nicc);

			MessageDigest digest;
			try
			{
				digest = MessageDigest.getInstance("sha256");
			}
			catch (Exception e)
			{
				MainActivity.logger.error(TAG, "Unable to create sha256 digest", e);
				return null;
			}

			byte [] Iid=new byte[8];
			rand.nextBytes(Iid);
			byte [] Guid=new byte[16];
			rand.nextBytes(Guid);

			//Create CVC:
			byte[] Cicc=ByteUtil.concatenate(
					ByteUtil.hexStringToByteArray("7F 21 5F 29 01 80 42 08"),
					Iid,//Issuer ID
					//ByteUtil.hexStringToByteArray("01 01 01 01 01 01 01 01"), //Issuer ID
					ByteUtil.hexStringToByteArray("5F 20 10"),
					Guid,//GUID
					// ByteUtil.hexStringToByteArray("30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30"), //GUID
					ByteUtil.hexStringToByteArray("7F 49"),
					ByteUtil.hexStringToByteArray(String.format("%02X 06 05",clientPublicKey.length+8)),
					ByteUtil.hexStringToByteArray("2B 81 04 00 22"), //Algorithm OID for ECDH P-256
					ByteUtil.hexStringToByteArray("86 "+String.format("%02X",clientPublicKey.length)),
					clientPublicKey,
					ByteUtil.hexStringToByteArray("5F 4C 01 00")
			);

			Signature cvcSigner= Signature.getInstance("ECDSA");
			cvcSigner.initSign(ecPriv,new SecureRandom());
			cvcSigner.update(Cicc);
			byte[] cvcSig=cvcSigner.sign();

			Cicc=ByteUtil.concatenate(Cicc,
					ByteUtil.hexStringToByteArray("5F 37"),
					Opacity.berTlvEncodeLen(cvcSig.length),
					cvcSig);

			byte[] IDicc=Arrays.copyOf(digest.digest(Cicc),8);


			String IDh=ByteUtil.toHexString(requestAPDU,10,18," ");

			String otherInfo =
					"04 0D 0D 0D 0D 08 " +
							IDh +
							" 01 " +
							" 00 " + //CBh
							" 10 " +
							ByteUtil.toHexString(hostPubKey.getEncoded(), 24, 40, " ") +
							" 08 " +
							ByteUtil.toHexString(IDicc, " ") +
							" 18 " +
							ByteUtil.toHexString(Nicc, " ") +
							" 01 " +
							ByteUtil.toHexString(CBicc, " ");

			HashMap<String,byte[]> sessionKeys;

			byte[] kdf = Opacity.kdf(z, 1024, ByteUtil.hexStringToByteArray(otherInfo),"sha384");
			//logger.info(TAG, "kdf = " + ByteUtil.toHexString(kdf, " "));
			sessionKeys = Opacity.kdfToDict(kdf);

			z=new byte[]  {0x00};

			logger.newLine();
			logger.info(TAG, "Session keys:");
			logger.info(TAG, "    CFRM: " + ByteUtil.toHexString(sessionKeys.get("cfrm"), " "));
			logger.info(TAG, "    MAC: " + ByteUtil.toHexString(sessionKeys.get("mac"), " "));
			logger.info(TAG, "    ENC: " + ByteUtil.toHexString(sessionKeys.get("enc"), " "));
			logger.info(TAG, "    RMAC: " + ByteUtil.toHexString(sessionKeys.get("rmac"), " "));

			// Create AuthCryptogramicc:
			byte[] message = ByteUtil.concatenate(
					ByteUtil.hexStringToByteArray("4B 43 5F 31 5F 56"), //"KC_1_V"
					IDicc,
					ByteUtil.hexStringToByteArray(IDh),
					Arrays.copyOfRange(hostPubKey.getEncoded(), 24,hostPubKey.getEncoded().length)
			);

			byte[] AuthCryptogramicc = new Cmac(sessionKeys.get("cfrm"), message).mac;

			sessionKeys.put("cfrm",new byte[] {0x00});


			long stopTime = System.currentTimeMillis();
			TunnelCreationTimer = (int) (stopTime - startTime);

			logger.newLine();
			logger.info(TAG, "Opacity Session Established in " + TunnelCreationTimer.toString() + " ms on client side");
			logger.newLine();

			byte[] payload=ByteUtil.concatenate(Opacity.berTlvEncodeLen(ByteUtil.concatenate(CBicc,Nicc,AuthCryptogramicc,Cicc).length),CBicc,Nicc,AuthCryptogramicc,Cicc);


			sessionKeys.put("pub",ByteUtil.concatenate(ByteUtil.hexStringToByteArray("7C"),
					Opacity.berTlvEncodeLen(payload.length+1),
					ByteUtil.hexStringToByteArray("82"),payload));

			return sessionKeys;
		}
	}
}