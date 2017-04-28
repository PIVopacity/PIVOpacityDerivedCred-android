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

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Build;
import android.os.Environment;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.widget.Toast;
import exponent.derivedcred.CA.DODCACert;
import exponent.derivedcred.opacity.AesParameters;
import exponent.derivedcred.opacity.Opacity;
import exponent.derivedcred.opacity.OpacitySecureTunnel;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import javax.security.auth.x500.X500Principal;


public class DeriveCred implements NfcAdapter.ReaderCallback
{
    private Activity activity;
	private Logger logger;
    private Integer daysValid;
    private String flavor;

	private final static String TAG = "DeriveCred";

	private final static String GET_DISCOVERY_OBJECT = "00 CB 3F FF 03 5C 01 7E 00";
	private final static String MCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes
	private final static String RMCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes

	private final static String ERROR_TITLE = "Error";
	private final static String SUCCESS_TITLE = "SUCCESS";
	private final static String CARD_COMM_ERROR = "Error communicating with card: check log for details.";
	private final static String CRYPTO_ERROR = "Cryptography error: check log for details.";
    private final static String AUTH_ERROR = "Authentication error: check log for details.";

    private String keystoreCondition=null;

	public DeriveCred(Activity activity, Logger logger, Integer days, String flavor)
	{
        this.activity = activity;
		this.logger = logger;
        this.daysValid = days;
        this.flavor=flavor;
        Toast.makeText(this.activity,"Hold PIV Card to NFC Antenna",Toast.LENGTH_LONG).show();
	}

	/**
	 * Called when the NFC system finds a tag.
	 * @param tag the discovered NFC tag
	 */
	@RequiresApi(api = Build.VERSION_CODES.M)
    @Override
	public void onTagDiscovered(Tag tag)
    {
        Transceiver.Response response;
        logger.clear();

        logger.info(TAG, "Card Detected on Reader: " + StringUtil.join(tag.getTechList(), ", "));

        Transceiver transceiver = Transceiver.create(logger, tag);
        if (null == transceiver)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            return;
        }

        // Select the PIV Card Application:
        response = transceiver.transceive("SELECT PIV AID", Opacity.SELECT_PIV);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }
        byte opacFlav=response.data[response.data.length-4];

        // Open an Opacity secure tunnel, receiving the session keys:
        OpacitySecureTunnel opacityTunnel = new OpacitySecureTunnel(logger);
        HashMap<String, byte[]> sessionKeys;

        try
        {
            sessionKeys = opacityTunnel.openTunnel(transceiver,opacFlav);
            if (sessionKeys == null)
            {
                logger.error(TAG, "Unable to generate Opacity session keys");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to establish Opacity Secure Tunnel", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        logger.newLine();
        logger.info(TAG, "*** Begin secure messaging using AES-128 ***");
        logger.newLine();

        // Get the discovery object in the clear

        response = transceiver.transceive("Get Discovery object in clear", GET_DISCOVERY_OBJECT);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        byte[] discoveryObject = response.data;

        // Secure messaging using AES-128
        // NIST SP800-73-4 says this should start at 1 (Part 2, Page 32)
        int encCount = 1;
        AesParameters encryptionParameters;
        try
        {
            encryptionParameters = new AesParameters(encCount, ByteUtil.hexStringToByteArray(MCV), ByteUtil.hexStringToByteArray(RMCV), sessionKeys);
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to create AES Cipher", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        byte[][] encryptedApdu;
        byte[] decryptedResponse;
        String transaction;

        // Check for need for pairing code:
        if ((0xf & discoveryObject[discoveryObject.length - 2]) == 0x8)
        {
            logger.newLine();
            transaction = "Verify Pairing Code";
            logger.info(TAG, transaction);

            GetNumericInputDialogFragment fragment = GetNumericInputDialogFragment.create("Enter Pairing Code (data encrypted in transit)");
            String input = fragment.showDialog(activity);
            fragment.dismiss();

            if (null == input)
            {
                logger.error(TAG, "Unable to get Pairing Code from user");
                logger.alert("Unable to get Pairing Code from user: try again.", ERROR_TITLE);
                transceiver.close();
                return;
            }

            logger.info(TAG, "Pairing code: " + input);
            byte[] pairingCode = input.getBytes();
            if (pairingCode.length != 8)
            {
                logger.error(TAG, "Pairing Code is too short or too long");
                logger.alert("Pairing code is too short or too long: try again", ERROR_TITLE);
                transceiver.close();
                return;
            }

            try
            {
                encryptedApdu = Opacity.encryptApdu(
                        encryptionParameters,
                        new byte[]{(byte) 0x20},
                        new byte[1],
                        new byte[]{(byte) 0x98},
                        pairingCode,
                        null);
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to encrypt Pairing Code APDU", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Pairing Code response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            if (!response.isWrappedStatusSuccess())
            {
                logger.error(TAG, "Pairing Code verification failed");
                logger.alert("Pairing code verification failed.", ERROR_TITLE);
                transceiver.close();
                return;
            }

            encryptionParameters.count++;
        }


        // Get the X.509 certificate for PIV authentication:

        logger.newLine();
        transaction = "Get X.509 Cert. for PIV Auth.";
        logger.info(TAG, transaction);

        X509Certificate pivCert = null;
        X509Certificate dodCaCert = new DODCACert().getDODCert();

        File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PIV_Auth_Cert_" + ByteUtil.toHexString(opacityTunnel.cardSignature.id) + ".der");
        FileOutputStream fos = null;

        if(file.exists())
        {
            try
            {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                FileInputStream fis;
                try
                {
                    fis = new FileInputStream(file);
                } catch (FileNotFoundException e)
                {
                    e.printStackTrace();
                    return;
                }
                pivCert = (X509Certificate) cf.generateCertificate(fis);

                try
                {
                    pivCert.checkValidity();
                    pivCert.verify(dodCaCert.getPublicKey());
                    //Should do Cert CRL check here, will implement at a later date.
                }catch(Exception ex)
                {
                    logger.error(ERROR_TITLE,"PIV Auth. Certificate Invalid! "+ex.toString());
                    logger.alert(AUTH_ERROR,ERROR_TITLE);
                    transceiver.close();
                    return;
                }

                logger.info(TAG, "Stored PIV Auth. Cert:\n" + pivCert.toString());




            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to decrypt response", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }
        }
        else
        {
            try
            {
                encryptedApdu = Opacity.encryptApdu(
                        encryptionParameters,
                        ByteUtil.hexStringToByteArray("CB"),
                        ByteUtil.hexStringToByteArray("3F"),
                        ByteUtil.hexStringToByteArray("FF"),
                        ByteUtil.hexStringToByteArray("5C 03 5F C1 05"),
                        null);
            } catch (Exception ex)
            {
                logger.error(TAG, "Unable to encrypt APDU", ex);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }

            try
            {
                decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
                if (null != decryptedResponse)
                {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream bis = new ByteArrayInputStream(Arrays.copyOfRange(decryptedResponse, 8, 8 + (((decryptedResponse[6] & 0xFF) << 8) | (decryptedResponse[7] & 0xFF))));
                    pivCert = (X509Certificate) cf.generateCertificate(bis);

                    try
                    {
                        pivCert.checkValidity();
                        pivCert.verify(dodCaCert.getPublicKey());
                        //Should do Cert CRL check here, will implement at a later date.
                    } catch (Exception ex)
                    {
                        logger.error(ERROR_TITLE, "PIV Auth. Certificate Invalid! " + ex.toString());
                        logger.alert(AUTH_ERROR, ERROR_TITLE);
                        transceiver.close();
                        return;
                    }

                    logger.info(TAG, "Decrypted response:\n" + pivCert.toString());


                }
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to decrypt response", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                return;
            }
            try
            {
                fos = new FileOutputStream(file);
                // Writes bytes from the specified byte array to this file output stream
                try
                {
                    fos.write(pivCert.getEncoded());
                } catch (CertificateEncodingException e)
                {
                    e.printStackTrace();
                }
            } catch (FileNotFoundException e)
            {
                System.out.println("File not found" + e);
            } catch (IOException ioe)
            {
                System.out.println("Exception while writing file " + ioe);
            } finally
            {
                // Make sure the stream is closed:
                try
                {
                    if (fos != null)
                    {
                        fos.close();
                    }
                } catch (IOException ioe)
                {
                    System.out.println("Error while closing stream: " + ioe);
                }
            }
            logger.info(TAG, "PIV Auth. Cert. Path: " + file.getPath());
            encryptionParameters.count++;
        }

        Calendar cal = Calendar.getInstance();
        Date startDate = cal.getTime();                // time from which certificate is valid
        cal.add(cal.DATE,daysValid);
        Date expiryDate = cal.getTime();               // time after which certificate is not valid
        BigInteger serialNumber = new BigInteger(40,new SecureRandom());       // serial number for certificate

        X500Principal subName=new X500Principal(pivCert.getSubjectDN().toString());

        RSAKeyGenParameterSpec rsaSpec2048 = new RSAKeyGenParameterSpec(2048,new BigInteger("65537"));

        KeyPairGenerator kpg = null;
        KeyPair rsaHolder=null;
        try
        {
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(rsaSpec2048, new SecureRandom());
            rsaHolder=kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e)
        {
            e.printStackTrace();
        }


        //Derived Credential Key
        //secp224r1, prime 256: prime256v1, prime 384: secp384r1, prime 512: secp521r1
        KeyPair pair=null;
        long start=System.currentTimeMillis();
        if(flavor.startsWith("RSA"))
        {
            //AKS
            try
            {
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,"AndroidKeyStore");
                kpg.initialize(new KeyGenParameterSpec.Builder(
                        "derivedPivKey",
                        KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_VERIFY)
                        .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(Integer.parseInt(flavor.substring(4)),new BigInteger("65537")))
                        .setDigests(KeyProperties.DIGEST_NONE,KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA384,KeyProperties.DIGEST_SHA512)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setRandomizedEncryptionRequired(true)
                        .setCertificateSubject(subName)
                        .setCertificateSerialNumber(serialNumber)
                        .setCertificateNotBefore(startDate)
                        .setCertificateNotAfter(expiryDate)
                        .setAttestationChallenge(null)
                        // Only permit the private key to be used if the user authenticated
                        // within the last five minutes.
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationValidityDurationSeconds(5 * 60)
                        .build());
            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e)
            {
                e.printStackTrace();
            } catch (NoSuchProviderException e)
            {
                e.printStackTrace();
            }

            pair=kpg.generateKeyPair(); // public/private key pair that we are creating for credential
        } else if(flavor.startsWith("ECC"))
        {
            //AKS
            try
            {
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore");
                kpg.initialize(new KeyGenParameterSpec.Builder(
                    "derivedPivKey",
                    KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec(flavor.substring(4)))
                    .setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA384,KeyProperties.DIGEST_SHA512)
                    .setCertificateSubject(subName)
                    .setCertificateSerialNumber(serialNumber)
                    .setCertificateNotBefore(startDate)
                    .setCertificateNotAfter(expiryDate)
                    .setAttestationChallenge(null)
                    // Only permit the private key to be used if the user authenticated
                    // within the last five minutes.
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(5 * 60)
                    .build());

            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e)
            {
                e.printStackTrace();
            } catch (NoSuchProviderException e)
            {
                e.printStackTrace();
            }

            pair=kpg.generateKeyPair(); // public/private key pair that we are creating for credential

        }else
        {
            logger.error(TAG, "Crypto Error");
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }
        logger.info(TAG,"Key generation time: "+(System.currentTimeMillis()-start)+" ms");

        KeyFactory factory = null;
        try
        {
            factory = KeyFactory.getInstance(pair.getPrivate().getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo;
            try {
                keyInfo = factory.getKeySpec(pair.getPrivate(), KeyInfo.class);
                if(keyInfo.isInsideSecureHardware())
                {
                    keystoreCondition="Private Key Stored In Secure Hardware";
                }else
                {
                    keystoreCondition="Private Key Stored In Software";
                }

            } catch (InvalidKeySpecException e) {
                // Not an Android KeyStore key.
            }
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (NoSuchProviderException e)
        {
            e.printStackTrace();
        }

        logger.info(TAG,keystoreCondition);


        KeyStore ks = null;

        try
        {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        }

        file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PIV_Auth_KeyStore");

        try
        {
            if(file.exists())
            {
                ks.load(new FileInputStream(file),null);
            } else
            {
                ks.load(null);
            }
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        }


        try
        {
            ks.setCertificateEntry("pivCert",pivCert);
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        }


        X509v3CertificateBuilder certGen =
                new JcaX509v3CertificateBuilder(pivCert,serialNumber,startDate,expiryDate,subName,pair.getPublic());
        X509Certificate derivedCert = null;
        try
        {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rsaHolder.getPrivate());
            derivedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(signer));

        } catch (OperatorCreationException e)
        {
            e.printStackTrace();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        }

        //logger.info(TAG,"CertGen: "+derivedCert.toString());

        // Get the PIN from the user and verify it:

        logger.newLine();
        transaction = "Verify PIN";
        logger.info(TAG, transaction);

        GetNumericInputDialogFragment fragment = GetNumericInputDialogFragment.create("Enter PIN (data encrypted in transit)");
        String input = fragment.showDialog(activity);
        fragment.dismiss();


        if (null == input)
        {
            logger.error(TAG, "Unable to get PIN from user");
            logger.alert("Unable to get PIN from user: try again.", ERROR_TITLE);
            transceiver.close();
            return;
        }

        byte[] pin = input.getBytes();
        if (pin.length < 6 || pin.length > 8)
        {
            logger.error(TAG, "PIN is too short or too long");
            logger.alert("PIN is too short or too long: try again.", ERROR_TITLE);
            transceiver.close();
            return;
        } else if (pin.length < 8)
        {
            byte[] pad = new byte[8 - pin.length];
            Arrays.fill(pad, (byte) 0xff);
            pin = ByteUtil.concatenate(pin, pad);
        }

        try
        {
            encryptedApdu = Opacity.encryptApdu(
                    encryptionParameters,
                    new byte[]{(byte) 0x20},
                    new byte[1],
                    new byte[]{(byte) 0x80},
                    pin,
                    null);
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to encrypt PIN APDU", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        response = transceiver.transceive(transaction, encryptedApdu);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        if (!Opacity.confirmRmac(encryptionParameters, response.data))
        {
            logger.error(TAG, "Check of PIN response CMAC failed");
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        if (!response.isWrappedStatusSuccess())
        {
            logger.error(TAG, "PIN verification failed");
            logger.alert("PIN verification failed: try again.", ERROR_TITLE);
            transceiver.close();
            return;
        } else
        {
            logger.info(TAG,"Virtual Contact Interface Open\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using "+Opacity.getAesType(opacFlav)+")\n");
        }

        encryptionParameters.count++;

        logger.newLine();
        transaction = "PIV Auth. Challenge with 32-Byte Digest & Derived Cert Signature";
        logger.info(TAG, transaction);
        long sigStartTime = System.currentTimeMillis();

        MessageDigest sha= null;
        byte[] unsignedCert= new byte[1000];
        try
        {
            unsignedCert = Arrays.copyOfRange(derivedCert.getEncoded(),0,derivedCert.getEncoded().length - 256);
            logger.info(TAG,"Unsigned Cert: "+ByteUtil.toHexString(unsignedCert," "));
        } catch (CertificateEncodingException e)
        {
            e.printStackTrace();
        }
        byte[] digestInfo=new byte[32];
        try
        {
            sha = MessageDigest.getInstance("SHA-256");
            digestInfo=ByteUtil.concatenate(ByteUtil.hexStringToByteArray("3031300d060960864801650304020105000420"),sha.digest(derivedCert.getTBSCertificate()));//RFC 3447 Sec. 9.2 for DigestInfo
            logger.info(TAG,"SHA256:  "+ByteUtil.toHexString(digestInfo," "));
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (CertificateEncodingException e)
        {
            e.printStackTrace();
        }

        RSAKey hostPubKey= (RSAKey)pivCert.getPublicKey();

        byte[] payload = ByteUtil.hexStringToByteArray("7C" + "820106" + "8200" + "81820100");
        payload = ByteUtil.concatenate(payload, Opacity.pkcs1v15Pad("01", digestInfo, hostPubKey.getModulus().bitLength()));
        try
        {
            encryptedApdu = Opacity.encryptApdu(
                    encryptionParameters,
                    ByteUtil.hexStringToByteArray("87"),
                    ByteUtil.hexStringToByteArray("07"),
                    ByteUtil.hexStringToByteArray("9A"),
                    payload,
                    new byte[]{(byte) 0x00});
        } catch (Exception ex)
        {
            logger.error(TAG, "Unable to encrypt APDU", ex);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        response = transceiver.transceive(transaction, encryptedApdu);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        if (!Opacity.confirmRmac(encryptionParameters, response.data))
        {
            logger.error(TAG, "Check of Response CMAC failed");
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }

        try
        {
            decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
            if (null != decryptedResponse)
            {
                logger.info(TAG, "Decrypted response: " + ByteUtil.toHexString(decryptedResponse, " "));
            }
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to decrypt response", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            return;
        }
        encryptionParameters.count++;

        Signature sig = null;
        try
        {
            sig = Signature.getInstance("NONEwithRSA");
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        if(null!=sig)
        {
            try
            {
                sig.initVerify(pivCert);
            } catch (InvalidKeyException e)
            {
                e.printStackTrace();
            }


            try
            {
                sig.update(digestInfo);
            } catch (SignatureException e)
            {
                e.printStackTrace();
            }

            try
            {
                if (sig.verify(decryptedResponse, 8, 256))
                {
                    logger.info(TAG, "PIV Challenge Valid");
                } else
                {
                    logger.info(TAG, "PIV Challenge Invalid");
                    logger.alert(AUTH_ERROR, ERROR_TITLE);
                    transceiver.close();
                    return;
                }
            } catch (SignatureException e)
            {
                e.printStackTrace();
            }
        }

        long sigStopTime=System.currentTimeMillis();

        X509Certificate derivedPivCert=null;
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bis = new ByteArrayInputStream(ByteUtil.concatenate(unsignedCert,Arrays.copyOfRange(decryptedResponse,8,256+8)));

            derivedPivCert = (X509Certificate) cf.generateCertificate(bis);
            ks.setCertificateEntry("derivedPivCert",derivedPivCert);
            logger.newLine();
            logger.newLine();
            logger.info(TAG,"Derived PIV Cert:\n\n"+ks.getCertificate("derivedPivCert").toString());

        } catch (CertificateException e)
        {
            e.printStackTrace();
        }  catch (KeyStoreException e)
        {
            e.printStackTrace();
        }

        try
        {
            X509Certificate test = (X509Certificate) ks.getCertificate("derivedPivCert");
            sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(ks.getCertificate("pivCert"));
            sig.update(test.getTBSCertificate());
            logger.info(TAG,"Sig Verified with PIV Cert: "+sig.verify(test.getSignature()));
        } catch (CertificateException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (InvalidKeyException e)
        {
            e.printStackTrace();
        }catch (SignatureException e)
        {
            e.printStackTrace();
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        }


        try
        {
            ks.store(new FileOutputStream(file),null);
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        }

        logger.alert("Contactless PIV Authentication\nFIPS 201 Level 4 Assurance\n\nTemporary Credential Derived\nNIST SP 800-157 Level 3\n"+keystoreCondition+"\n\nRSA Challenge Time: " + (sigStopTime - sigStartTime) + " ms\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using "+Opacity.getAesType(opacFlav)+")\n", SUCCESS_TITLE);

        Log.d(TAG, "Disabling reader mode");
        NfcAdapter nfc = NfcAdapter.getDefaultAdapter(this.activity);
        if (nfc != null)
        {
            nfc.disableReaderMode(this.activity);
        }

    }


}
