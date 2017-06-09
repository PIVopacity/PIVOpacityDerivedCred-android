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
import android.os.Environment;
import android.util.Log;
import exponent.derivedcred.CA.DODCACert;
import exponent.derivedcred.opacity.AesParameters;
import exponent.derivedcred.opacity.Opacity;
import exponent.derivedcred.opacity.OpacitySecureTunnel;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.HashMap;


/**
 * Provides access to the Common Access Card reader.
 */
public class CacReader implements NfcAdapter.ReaderCallback
{
    private Activity activity;
	private Logger logger;

	private final static String TAG = "CacReader";

    private final static int NFC_READER_FLAGS = NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;

	private final static String GET_DISCOVERY_OBJECT = "00 CB 3F FF 03 5C 01 7E 00";
	private final static String MCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes
	private final static String RMCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes

	private final static String ERROR_TITLE = "Error";
	private final static String SUCCESS_TITLE = "SUCCESS";
	private final static String CARD_COMM_ERROR = "Error communicating with card: check log for details.";
	private final static String CRYPTO_ERROR = "Cryptography error: check log for details.";
    private final static String AUTH_ERROR = "Authentication error: check log for details.";

    public boolean isTagDiscovered=false;

    public CacReader(Activity activity, Logger logger)
	{
        this.activity = activity;
		this.logger = logger;
    }

    private void nfcClose()
    {
        Log.d(TAG, "Disabling reader mode");
        NfcAdapter nfc = NfcAdapter.getDefaultAdapter(this.activity);
        if (nfc != null)
        {
            nfc.disableReaderMode(this.activity);
        }
    }


	/**
	 * Called when the NFC system finds a tag.
	 * @param tag the discovered NFC tag
	 */
	@Override
	public void onTagDiscovered(Tag tag)
    {

        Transceiver.Response response;
        logger.clear();
        isTagDiscovered=true;
        logger.info(TAG, "Card Detected on Reader: " + StringUtil.join(tag.getTechList(), ", "));

        Transceiver transceiver = Transceiver.create(logger, tag);
        if (null == transceiver)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            nfcClose();
            return;
        }

        // Select the PIV Card Application:



        response = transceiver.transceive("SELECT PIV AID", Opacity.SELECT_PIV);
        if (null == response)
        {
            logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
            transceiver.close();
            nfcClose();
            return;
        }
        byte[] selectResp=response.data;
        byte opacFlav=0x00;
        if(ByteUtil.toHexString(response.data,ByteUtil.toHexString(response.data).toUpperCase().indexOf("AC")/2,response.data.length).toUpperCase().contains("2E"))
            opacFlav=0x2E;
        else if(ByteUtil.toHexString(response.data,ByteUtil.toHexString(response.data).toUpperCase().indexOf("AC")/2,response.data.length).toUpperCase().contains("27"))
            opacFlav=0x27;

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
                nfcClose();
                return;
            }
        } catch (GeneralSecurityException e)
        {
            logger.error(TAG, "Unable to establish Opacity Secure Tunnel", e);
            logger.alert(CRYPTO_ERROR, ERROR_TITLE);
            transceiver.close();
            nfcClose();
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
            nfcClose();
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
            nfcClose();
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
                nfcClose();
                return;
            }

            logger.info(TAG, "Pairing code: " + input);
            byte[] pairingCode = input.getBytes();
            if (pairingCode.length != 8)
            {
                logger.error(TAG, "Pairing Code is too short or too long");
                logger.alert("Pairing code is too short or too long: try again", ERROR_TITLE);
                transceiver.close();
                nfcClose();
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
                nfcClose();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Pairing Code response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!response.isWrappedStatusSuccess())
            {
                logger.error(TAG, "Pairing Code verification failed");
                logger.alert("Pairing code verification failed.", ERROR_TITLE);
                transceiver.close();
                nfcClose();
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

        File directory=new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),"Auth/");
        if(!directory.exists())
        {
            directory.mkdir();
        }
        File file = new File(directory.getPath(), "PIV_Auth_Cert_"+ByteUtil.toHexString(opacityTunnel.cardSignature.id)+".der");
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
                    logger.error(ERROR_TITLE,"Stored PIV Auth. Certificate Invalid! "+ex.toString());
                    logger.alert(AUTH_ERROR,ERROR_TITLE);
                    file.delete();
                    transceiver.close();
                    nfcClose();
                    return;
                }

                logger.info(TAG, "Stored PIV Auth. Cert:\n" + pivCert.toString());




            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to decrypt response", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
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
                nfcClose();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
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
                        nfcClose();
                        return;
                    }

                    logger.info(TAG, "Decrypted response:\n" + pivCert.toString());


                }
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to decrypt response", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
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
            }catch (FileNotFoundException e)
            {
                System.out.println("File not found" + e);
            }
            catch (IOException ioe)
            {
                System.out.println("Exception while writing file " + ioe);
            }
            finally
            {
                // Make sure the stream is closed:
                try
                {
                    if (fos != null)
                    {
                        fos.close();
                    }
                }
                catch (IOException ioe)
                {
                    System.out.println("Error while closing stream: " + ioe);
                }
            }
            logger.info(TAG, "PIV Auth. Cert. Path: " + file.getPath());
            encryptionParameters.count++;
        }

        // Get the Derived X.509 certificate for PIV authentication:
        X509Certificate derivedPivCert = pivCert;

        if(Arrays.equals(ByteUtil.hexStringToByteArray("9999999999"),Arrays.copyOf(selectResp,5)))
        {
            logger.newLine();
            transaction = "Get Derived X.509 Cert. for PIV Auth.";
            logger.info(TAG, transaction);

            file = new File(directory.getPath(), "Derived_PIV_Auth_Cert_"+ByteUtil.toHexString(opacityTunnel.cardSignature.id)+".der");
            fos = null;

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
                    derivedPivCert = (X509Certificate) cf.generateCertificate(fis);

                    try
                    {
                        if(!(derivedPivCert.getSubjectDN().toString().equals(pivCert.getSubjectDN().toString())))
                        {
                            throw new CertificateException("Subject DN do not match!");
                        }
                        derivedPivCert.checkValidity();
                        derivedPivCert.verify(pivCert.getPublicKey());
                    }catch(Exception ex)
                    {
                        logger.error(ERROR_TITLE,"Stored Derived PIV Auth. Certificate Invalid! "+ex.toString());
                        logger.alert(AUTH_ERROR,ERROR_TITLE);
                        file.delete();
                        transceiver.close();
                        nfcClose();
                        return;
                    }

                    logger.info(TAG, "Stored Derived PIV Auth. Cert:\n" + derivedPivCert.toString());




                } catch (GeneralSecurityException e)
                {
                    logger.error(TAG, "Unable to decrypt response", e);
                    logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                    transceiver.close();
                    nfcClose();
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
                            ByteUtil.hexStringToByteArray("5C 03 5F C1 99"),
                            null);
                } catch (Exception ex)
                {
                    logger.error(TAG, "Unable to encrypt APDU", ex);
                    logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                    transceiver.close();
                    nfcClose();
                    return;
                }

                response = transceiver.transceive(transaction, encryptedApdu);
                if (null == response)
                {
                    logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                    transceiver.close();
                    nfcClose();
                    return;
                }

                if (!Opacity.confirmRmac(encryptionParameters, response.data))
                {
                    logger.error(TAG, "Check of Response CMAC failed");
                    logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                    transceiver.close();
                    nfcClose();
                    return;
                }

                try
                {
                    decryptedResponse = Opacity.getDecryptedResponse(encryptionParameters, response.data);
                    if (null != decryptedResponse)
                    {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        ByteArrayInputStream bis = new ByteArrayInputStream(Arrays.copyOfRange(decryptedResponse, 8, 8 + (((decryptedResponse[6] & 0xFF) << 8) | (decryptedResponse[7] & 0xFF))));
                        derivedPivCert = (X509Certificate) cf.generateCertificate(bis);

                        try
                        {
                            if(!(derivedPivCert.getSubjectDN().toString().equals(pivCert.getSubjectDN().toString())))
                            {
                                throw new CertificateException("Subject DN do not match!");
                            }
                            derivedPivCert.checkValidity();
                            derivedPivCert.verify(pivCert.getPublicKey());
                        } catch (Exception ex)
                        {
                            logger.error(ERROR_TITLE, "PIV Auth. Certificate Invalid! " + ex.toString());
                            logger.alert(AUTH_ERROR, ERROR_TITLE);
                            transceiver.close();
                            nfcClose();
                            return;
                        }

                        logger.info(TAG, "Decrypted response:\n" + derivedPivCert.toString());


                    }
                } catch (GeneralSecurityException e)
                {
                    logger.error(TAG, "Unable to decrypt response", e);
                    logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                    transceiver.close();
                    nfcClose();
                    return;
                }
                try
                {
                    fos = new FileOutputStream(file);
                    // Writes bytes from the specified byte array to this file output stream
                    try
                    {
                        fos.write(derivedPivCert.getEncoded());
                    } catch (CertificateEncodingException e)
                    {
                        e.printStackTrace();
                    }
                }catch (FileNotFoundException e)
                {
                    System.out.println("File not found" + e);
                }
                catch (IOException ioe)
                {
                    System.out.println("Exception while writing file " + ioe);
                }
                finally
                {
                    // Make sure the stream is closed:
                    try
                    {
                        if (fos != null)
                        {
                            fos.close();
                        }
                    }
                    catch (IOException ioe)
                    {
                        System.out.println("Error while closing stream: " + ioe);
                    }
                }
                logger.info(TAG, "PIV Auth. Cert. Path: " + file.getPath());
                encryptionParameters.count++;
            }
        }





        // Get the PIN from the user:
        if(!Arrays.equals(ByteUtil.hexStringToByteArray("9999999999"),Arrays.copyOf(selectResp,5)))
        {
            GetNumericInputDialogFragment fragment = GetNumericInputDialogFragment.create("Enter PIN (data encrypted in transit)");
            String input = fragment.showDialog(activity);
            fragment.dismiss();
            if (null == input)
            {
                logger.error(TAG, "Unable to get PIN from user");
                logger.alert("Unable to get PIN from user: try again.", ERROR_TITLE);
                return;
            }

             byte[] pin = input.getBytes();
            input = null;
            if (pin.length < 6 || pin.length > 8)
            {
                logger.error(TAG, "PIN is too short or too long");
                logger.alert("PIN is too short or too long: try again.", ERROR_TITLE);
                pin = null;
                return;
            } else if (pin.length < 8)
            {
                byte[] pad = new byte[8 - pin.length];
                Arrays.fill(pad, (byte) 0xff);
                pin = ByteUtil.concatenate(pin, pad);
            }

            //Verify Pin
            logger.newLine();
            transaction = "Verify PIN";
            logger.info(TAG, transaction);

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
                nfcClose();
                return;
            }
            pin = null; //zeroize pin?
            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of PIN response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!response.isWrappedStatusSuccess())
            {
                logger.error(TAG, "PIN verification failed");
                logger.alert("PIN verification failed: try again.", ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            } else
            {
                logger.info(TAG, "Virtual Contact Interface Open\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using " + Opacity.getAesType(opacFlav) + ")\n");
            }

            encryptionParameters.count++;
        }

        logger.newLine();
        transaction = "PIV Auth. Challenge with 192-Byte Nonce";
        logger.info(TAG, transaction);
        long sigStartTime = System.currentTimeMillis();
        byte[] nonce=new byte[192];

        SecureRandom rand=new SecureRandom();
        rand.nextBytes(nonce);

       if(derivedPivCert.getPublicKey().getAlgorithm().equals("RSA"))
        {
            RSAKey hostPubKey = (RSAKey) derivedPivCert.getPublicKey();

            byte[] payload = Opacity.pkcs1v15Pad("01", nonce, hostPubKey.getModulus().bitLength());
            payload = ByteUtil.concatenate(new byte[] {(byte) 0x81}, Opacity.berTlvEncodeLen(payload.length),payload);
            payload = ByteUtil.concatenate(new byte[] {(byte)0x7C},
                    Opacity.berTlvEncodeLen(payload.length+2),
                    new byte[] {(byte)0x82,(byte)0x00},
                    payload);


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
                nfcClose();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
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
                nfcClose();
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
            if (null != sig)
            {
                try
                {
                    sig.initVerify(derivedPivCert);
                } catch (InvalidKeyException e)
                {
                    e.printStackTrace();
                }


                try
                {
                    sig.update(nonce);
                } catch (SignatureException e)
                {
                    e.printStackTrace();
                }

                try
                {
                    int i=1+Opacity.berTlvTagLen(decryptedResponse[1]);
                    if (sig.verify(decryptedResponse,i+Opacity.berTlvTagLen(decryptedResponse[i+1])+1 , Opacity.berTlvParseLen(Arrays.copyOfRange(decryptedResponse,i+1,i+6))))
                    {
                        logger.info(TAG, "PIV Challenge Valid");
                        logger.alert("Contactless PIV Authentication\nFIPS 201 Level 4 Assurance\n\nRSA Challenge Time: " + (System.currentTimeMillis() - sigStartTime) + " ms\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using "+Opacity.getAesType(opacFlav)+")\n", SUCCESS_TITLE);
                    } else
                    {
                        logger.info(TAG, "PIV Challenge Invalid");
                        logger.alert(AUTH_ERROR, ERROR_TITLE);
                        transceiver.close();
                        nfcClose();
                        return;
                    }
                } catch (SignatureException e)
                {
                    e.printStackTrace();
                }
            }
        } else if(derivedPivCert.getPublicKey().getAlgorithm().equals("EC"))
        {
            byte[] payload = ByteUtil.concatenate(new byte[] {(byte) 0x81}, Opacity.berTlvEncodeLen(nonce.length),nonce);
            payload = ByteUtil.concatenate(new byte[] {(byte)0x7C},
                    Opacity.berTlvEncodeLen(payload.length+2),
                    new byte[] {(byte)0x82,(byte)0x00},
                    payload);

            try
            {
                encryptedApdu = Opacity.encryptApdu(
                        encryptionParameters,
                        ByteUtil.hexStringToByteArray("87"),
                        ByteUtil.hexStringToByteArray("11"),
                        ByteUtil.hexStringToByteArray("9A"),
                        payload,
                        new byte[]{(byte) 0x00});
            } catch (Exception ex)
            {
                logger.error(TAG, "Unable to encrypt APDU", ex);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            response = transceiver.transceive(transaction, encryptedApdu);
            if (null == response)
            {
                logger.alert(CARD_COMM_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
                return;
            }

            if (!Opacity.confirmRmac(encryptionParameters, response.data))
            {
                logger.error(TAG, "Check of Response CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                transceiver.close();
                nfcClose();
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
                nfcClose();
                return;
            }
            encryptionParameters.count++;

            Signature sig = null;
            try
            {
                sig = Signature.getInstance("SHA256withECDSA");
            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
            if (null != sig)
            {
                try
                {
                    sig.initVerify(derivedPivCert);
                } catch (InvalidKeyException e)
                {
                    e.printStackTrace();
                }


                try
                {
                    sig.update(nonce);
                } catch (SignatureException e)
                {
                    e.printStackTrace();
                }

                try
                {
                    int i=1+Opacity.berTlvTagLen(decryptedResponse[1]);
                    if (sig.verify(decryptedResponse,i+Opacity.berTlvTagLen(decryptedResponse[i+1])+1 , Opacity.berTlvParseLen(Arrays.copyOfRange(decryptedResponse,i+1,i+6))))
                     {
                        logger.info(TAG, "PIV Challenge Valid");
                        logger.alert("Contactless PIV Authentication\nFIPS 201 Level 3 Assurance\n\nECDSA Challenge Time: " + (System.currentTimeMillis() - sigStartTime) + " ms\n\n" + "OPACITY Secure Tunnel\nestablished in: " + opacityTunnel.getCreationTime().toString() + " ms\n\n(secure messaging using "+Opacity.getAesType(opacFlav)+")\n", SUCCESS_TITLE);
                    } else
                    {
                        logger.info(TAG, "PIV Challenge Invalid");
                        logger.alert(AUTH_ERROR, ERROR_TITLE);
                        transceiver.close();
                        nfcClose();
                        return;
                    }
                } catch (SignatureException e)
                {
                    e.printStackTrace();
                }
            }
        } else
        {
            logger.error(TAG, "Unrecognized key algorithm");
            logger.alert("Unrecognized key algorithm.", ERROR_TITLE);
            transceiver.close();
            nfcClose();
            return;
        }


        nfcClose();
    }


}
