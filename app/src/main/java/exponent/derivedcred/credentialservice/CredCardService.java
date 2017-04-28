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

package exponent.derivedcred.credentialservice;


import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.os.Environment;
import android.security.keystore.UserNotAuthenticatedException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import exponent.derivedcred.MainActivity;
import exponent.derivedcred.PACSFragment;
import exponent.derivedcred.dhsdemo.ByteUtil;
import exponent.derivedcred.dhsdemo.Logger;
import exponent.derivedcred.opacity.AesParameters;
import exponent.derivedcred.opacity.Opacity;
import exponent.derivedcred.opacity.OpacitySecureTunnel;


public class CredCardService extends HostApduService
{
    public static Logger logger=MainActivity.logger;
    private final static String ERROR_TITLE = "Error";
    private final static String CRYPTO_ERROR = "Cryptography error: check log for details.";

    private static final String TAG = "CredentialService";
    private static final String PIV_AID="A00000030800001000";
    private static final String SELECT_APDU_HEADER="00A40400";
    private static final byte[] SW_OK = ByteUtil.hexStringToByteArray("9000");

    private static byte[] select_aid = ByteUtil.hexStringToByteArray(
            SELECT_APDU_HEADER +
                    String.format("%02X", PIV_AID.length() / 2) +
                    PIV_AID
    );

    private static final byte[] UNKNOWN_CMD_SW = ByteUtil.hexStringToByteArray("6F00");
    private static final byte[] NOT_FOUND_SW = ByteUtil.hexStringToByteArray("6A82");
    private static final byte[] SEC_STATUS_NOT_SATISFIED = ByteUtil.hexStringToByteArray("6982");

    private static final String PIV_CERT="5C035FC105";
    private static final String DERIVED_PIV_CERT="5C035FC199";
    private static final String DISCOBJ="00CB3FFF035C017E";
    private static final String GET_DATA="CB3FFF";
    private static final String MORE_DATA= "C00000";
    private static final String GEN_AUTH_PIV_SEC_MSG="872704";
    private static final String GEN_AUTH_PIV_SEC_MSG192="872E04";
    private static final String GEN_AUTH_PIV_RSA="87079A";
    private static final String GEN_AUTH_PIV_ECDSA="87119A";

    CardHelper ch=new CardHelper();
    HashMap<String, byte[]> sessionKeys;
    OpacitySecureTunnel opacTun=new OpacitySecureTunnel(logger);

    boolean more=false;

    private final static String MCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes
    private final static String RMCV = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; // 16 bytes
    int encCount = 1;
    AesParameters encryptionParameters;

    public static String opacityTag="2E";


    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras)
    {
        logger.newLine();

        if(((int)commandApdu[0]&0xF0)==0x10)
        {
            more=ch.setLongCommand(commandApdu);
            return SW_OK;
        } else if(more && ((int)commandApdu[0]&0xF0)==0x00)
        {
            more=ch.setLongCommand(commandApdu);
            commandApdu=ch.getLongCommand();
            ch.clearLongCommand();
        }

        logger.info(TAG,"APDU Received: "+ByteUtil.toHexString(commandApdu, " "));

        if (((int)commandApdu[0] & 0xF) == 0xC)
        {
            if (!Opacity.confirmCmac(encryptionParameters, commandApdu))
            {
                logger.error(TAG, "Check of CMAC failed");
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                return null;
            }

        }

        if (Arrays.equals(select_aid, Arrays.copyOf(commandApdu,select_aid.length)))
        {
            opacityTag=PACSFragment.opacityTag;
            if(opacityTag==null)
            {
                opacityTag="2E";
            }
            String resp = "9999999999"+"AC068001"+opacityTag+"060100";
            logger.info(TAG,"Sending ATR:  "+resp);
            return ByteUtil.concatenate(ByteUtil.hexStringToByteArray(resp), SW_OK);
        } else if(Arrays.equals(ByteUtil.hexStringToByteArray(MORE_DATA),Arrays.copyOfRange(commandApdu,1,1+MORE_DATA.length()/2)))
        {
            return ch.GetLongResponse(commandApdu);
        } else if(Arrays.equals(ByteUtil.hexStringToByteArray(GEN_AUTH_PIV_SEC_MSG),Arrays.copyOfRange(commandApdu,1,1+GEN_AUTH_PIV_SEC_MSG.length()/2)))
        {//General Authenticate for Secure Messaging

            try
            {
                sessionKeys=opacTun.openClientTunnel(commandApdu);
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }
            encCount = 1;
            try
            {
                encryptionParameters = new AesParameters(encCount, ByteUtil.hexStringToByteArray(MCV), ByteUtil.hexStringToByteArray(RMCV), sessionKeys);
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to create AES Cipher", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                return null;
            }
            logger.info(TAG,"Sending: "+ByteUtil.toHexString(sessionKeys.get("pub")," "));
            return ByteUtil.concatenate(sessionKeys.get("pub"),SW_OK);
        } else if(Arrays.equals(ByteUtil.hexStringToByteArray(GEN_AUTH_PIV_SEC_MSG192),Arrays.copyOfRange(commandApdu,1,1+GEN_AUTH_PIV_SEC_MSG192.length()/2)))
        {//General Authenticate for Secure Messaging

            try
            {
                sessionKeys=opacTun.openClientTunnel192(commandApdu);
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }
            encCount = 1;
            try
            {
                encryptionParameters = new AesParameters(encCount, ByteUtil.hexStringToByteArray(MCV), ByteUtil.hexStringToByteArray(RMCV), sessionKeys);
            } catch (GeneralSecurityException e)
            {
                logger.error(TAG, "Unable to create AES Cipher", e);
                logger.alert(CRYPTO_ERROR, ERROR_TITLE);
                return null;
            }
            logger.info(TAG,"Sending: "+ByteUtil.toHexString(sessionKeys.get("pub")," "));
            return ByteUtil.concatenate(sessionKeys.get("pub"),SW_OK);
        } else if(Arrays.equals(ByteUtil.hexStringToByteArray(GET_DATA),Arrays.copyOfRange(commandApdu,1,1+GET_DATA.length()/2)))
        {
            if(Arrays.equals(ByteUtil.hexStringToByteArray(DISCOBJ),Arrays.copyOfRange(commandApdu,0,DISCOBJ.length()/2)))
            {
                return ByteUtil.concatenate(ByteUtil.hexStringToByteArray("7E124F0BA0000003080000100001005F2F024C00"),SW_OK);
            } else
            {
                try
                {
                    return getDataPivCert(commandApdu);
                } catch (GeneralSecurityException e)
                {
                    e.printStackTrace();
                }
            }
        } else if(Arrays.equals(ByteUtil.hexStringToByteArray(GEN_AUTH_PIV_RSA),Arrays.copyOfRange(commandApdu,1,1+GEN_AUTH_PIV_RSA.length()/2)))
        {
            try
            {
                return getGenAuthRSA(commandApdu);
            } catch (KeyStoreException e)
            {
                e.printStackTrace();
            }
        } else if(Arrays.equals(ByteUtil.hexStringToByteArray(GEN_AUTH_PIV_ECDSA),Arrays.copyOfRange(commandApdu,1,1+GEN_AUTH_PIV_ECDSA.length()/2)))
        {
            try
            {
                return getGenAuthECDSA(commandApdu);
            } catch (KeyStoreException e)
            {
                e.printStackTrace();
            }
        }
        {
          return UNKNOWN_CMD_SW;
        }
    }

    @Override
    public void onDeactivated(int reason) {

    }

    private byte[] buildPivCertificate(String alias)
    {
        KeyStore ks = null;
        File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PIV_Auth_KeyStore");
        try
        {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());

            if(file.exists())
            {
                ks.load(new FileInputStream(file),null);
            } else
            {
                logger.error(TAG, "Derived PIV Keystore not found!");
                logger.alert("KEYSTORE ERROR", ERROR_TITLE);
                return null;
            }

        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        } catch (CertificateException e)
        {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        } catch (FileNotFoundException e)
        {
            e.printStackTrace();
        } catch (IOException e)
        {
            e.printStackTrace();
        }


        byte[] pivCertificate=new byte[] {(byte)0x71,(byte)0x01,(byte)0x00,(byte)0xFE,(byte)0x00};
        try
        {
            pivCertificate=ByteUtil.concatenate(new byte[] {(byte)0x70},
                    Opacity.berTlvEncodeLen(ks.getCertificate(alias).getEncoded().length),
                    ks.getCertificate(alias).getEncoded(),
                    pivCertificate);
        } catch (CertificateEncodingException e)
        {
            e.printStackTrace();
        } catch (KeyStoreException e)
        {
            e.printStackTrace();
        }
        return ByteUtil.concatenate(new byte[] {(byte)0x53},Opacity.berTlvEncodeLen(pivCertificate.length),pivCertificate);
    }

    private byte[] getDataPivCert(byte[] commandApdu) throws GeneralSecurityException
    {
        if(((int)commandApdu[0] & 0xF) == 0x0)
        {
            return SEC_STATUS_NOT_SATISFIED;
        } else if (((int)commandApdu[0] & 0xF) == 0xC)
        {
            byte[] decryptedCommand=new byte[0];
            byte[] resp = new byte[0];
            try
            {
                decryptedCommand = Opacity.getDecryptedCommand(encryptionParameters, commandApdu);
                logger.info(TAG, "Decrypted command: " + ByteUtil.toHexString(decryptedCommand, " "));
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }

            if(Arrays.equals(ByteUtil.hexStringToByteArray(PIV_CERT),Arrays.copyOfRange(decryptedCommand,0, PIV_CERT.length()/2)))
            {
                byte[] pc = buildPivCertificate("pivCert");

                if (null == pc)
                {
                    encryptionParameters.count++;
                    return Opacity.encryptResponse(encryptionParameters, null, NOT_FOUND_SW);
                }


                try
                {
                    resp = Opacity.encryptResponse(encryptionParameters, pc, SW_OK);
                } catch (GeneralSecurityException e)
                {
                    e.printStackTrace();
                }
            } else if(Arrays.equals(ByteUtil.hexStringToByteArray(DERIVED_PIV_CERT),Arrays.copyOfRange(decryptedCommand,0, DERIVED_PIV_CERT.length()/2)))
            {
                byte[] pc = buildPivCertificate("derivedPivCert");

                if (null == pc)
                {
                    encryptionParameters.count++;
                    return Opacity.encryptResponse(encryptionParameters, null, NOT_FOUND_SW);
                }


                try
                {
                    resp = Opacity.encryptResponse(encryptionParameters, pc, SW_OK);
                } catch (GeneralSecurityException e)
                {
                    e.printStackTrace();
                }
            }


            ch.SetLongResponse(resp);
            encryptionParameters.count++;
            return ch.GetLongResponse(null);
        } else
        {
            return Opacity.encryptResponse(encryptionParameters,null,NOT_FOUND_SW);
        }
    }



    private byte[] getGenAuthRSA(byte[] commandApdu) throws KeyStoreException
    {
        if(((int)commandApdu[0] & 0xF) == 0x0)
        {
            return SEC_STATUS_NOT_SATISFIED;
        } else if (((int)commandApdu[0] & 0xF) == 0xC)
        {

            byte[] decryptedCommand=new byte[0];
            try
            {
                decryptedCommand = Opacity.getDecryptedCommand(encryptionParameters, commandApdu);
                logger.info(TAG, "Decrypted command: " + ByteUtil.toHexString(decryptedCommand, " "));
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }


            KeyStore ks = null;
            try
            {
                ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);

            } catch (KeyStoreException e)
            {
                e.printStackTrace();
            } catch (CertificateException e)
            {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (IOException e)
            {
                e.printStackTrace();
            }


            byte[] signature=new byte[0];

            try
            {
                int i=1+Opacity.berTlvTagLen(decryptedCommand[1])+2;
                //Deviation from 800-73-4:  PIV Card expects PKCS#1 v1.5 padding on payload, Android KeyStore policy does not allow signing without padding
                //                          must pass keystore an unpadded message.
                String paddedMsg=ByteUtil.toHexString(Arrays.copyOfRange(decryptedCommand,i+Opacity.berTlvTagLen(decryptedCommand[i+1])+1, i+Opacity.berTlvTagLen(decryptedCommand[i+1])+1+Opacity.berTlvParseLen(Arrays.copyOfRange(decryptedCommand,i+1,i+6))));
                Signature sig = Signature.getInstance("NONEwithRSA");
                sig.initSign((PrivateKey) ks.getKey("derivedPivKey",null),new SecureRandom());
                sig.update(ByteUtil.hexStringToByteArray(paddedMsg.substring(paddedMsg.indexOf("FF00")+4)));
                signature=sig.sign();

            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e)
            {
                logger.error(TAG, "Derived PIV Key Error");
                logger.alert("KEYSTORE ERROR", ERROR_TITLE);
                e.printStackTrace();
                return null;
            } catch (UserNotAuthenticatedException e)
            {
                logger.alert("User Not Authenticated!",ERROR_TITLE);
            } catch (InvalidKeyException e)
            {
                e.printStackTrace();
            } catch (UnrecoverableEntryException e)
            {
                e.printStackTrace();
            } catch (SignatureException e)
            {
                e.printStackTrace();
            }

            byte[] resp= new byte[0];

            byte[] signresp= ByteUtil.concatenate(Opacity.berTlvEncodeLen(signature.length),signature);
            signresp=ByteUtil.concatenate(ByteUtil.hexStringToByteArray("7C"),
                    Opacity.berTlvEncodeLen(signresp.length+1+Opacity.berTlvTagLen(Opacity.berTlvEncodeLen(signature.length)[0])),
                    ByteUtil.hexStringToByteArray("82"),
                    signresp);

            try
            {
                resp = Opacity.encryptResponse(encryptionParameters,signresp,SW_OK);
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }


            ch.SetLongResponse(resp);
            encryptionParameters.count++;
            return ch.GetLongResponse(null);
        } else
        {
            return NOT_FOUND_SW;
        }
    }


    private byte[] getGenAuthECDSA(byte[] commandApdu) throws KeyStoreException
    {
        if(((int)commandApdu[0] & 0xF) == 0x0)
        {
            return SEC_STATUS_NOT_SATISFIED;
        } else if (((int)commandApdu[0] & 0xF) == 0xC)
        {

            byte[] decryptedCommand = new byte[0];
            try
            {
                decryptedCommand = Opacity.getDecryptedCommand(encryptionParameters, commandApdu);
                logger.info(TAG, "Decrypted command: " + ByteUtil.toHexString(decryptedCommand, " "));
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }


            KeyStore ks = null;
            try
            {
                ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
            } catch (KeyStoreException e)
            {
                e.printStackTrace();
            } catch (CertificateException e)
            {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (FileNotFoundException e)
            {
                e.printStackTrace();
            } catch (IOException e)
            {
                e.printStackTrace();
            }

            byte[] signature = new byte[0];
            try
            {
                Signature sig = Signature.getInstance("SHA256withECDSA");
                sig.initSign((PrivateKey) ks.getKey("derivedPivKey", null));
                int i = 1 + Opacity.berTlvTagLen(decryptedCommand[1]) + 2;
                sig.update(Arrays.copyOfRange(decryptedCommand, i + Opacity.berTlvTagLen(decryptedCommand[i + 1]) + 1, i + Opacity.berTlvTagLen(decryptedCommand[i + 1]) + 1 + Opacity.berTlvParseLen(Arrays.copyOfRange(decryptedCommand, i + 1, i + 6))));
                signature = sig.sign();

            } catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e)
            {
                logger.error(TAG, "Derived PIV Key Error");
                logger.alert("KEYSTORE ERROR", ERROR_TITLE);
                e.printStackTrace();
                return null;
            } catch (UserNotAuthenticatedException e)
            {
                logger.alert("User Not Authenticated!",ERROR_TITLE);
            } catch (InvalidKeyException e)
            {
                e.printStackTrace();
            } catch (SignatureException e)
            {
                e.printStackTrace();
            } catch (UnrecoverableEntryException e)
            {
                e.printStackTrace();
            }


           byte[] resp= new byte[0];

            byte[] signresp= ByteUtil.concatenate(Opacity.berTlvEncodeLen(signature.length),signature);
            signresp=ByteUtil.concatenate(ByteUtil.hexStringToByteArray("7C"),
                    Opacity.berTlvEncodeLen(signresp.length+1+Opacity.berTlvTagLen(Opacity.berTlvEncodeLen(signature.length)[0])),
                    ByteUtil.hexStringToByteArray("82"),
                    signresp);

            try
            {
                resp = Opacity.encryptResponse(encryptionParameters,signresp,SW_OK);
            } catch (GeneralSecurityException e)
            {
                e.printStackTrace();
            }


            ch.SetLongResponse(resp);
            encryptionParameters.count++;
            return ch.GetLongResponse(null);
        } else
        {
            return NOT_FOUND_SW;
        }
    }


}



