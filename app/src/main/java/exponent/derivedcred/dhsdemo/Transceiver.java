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

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import java.io.IOException;
import java.util.Arrays;

/**
 * Provides mechanism for communicating with NFC tag.
 */
public class Transceiver
{
	private final static String TAG = "Transceiver";

	private IsoDep isoDep;
	private Logger logger;

	public final static byte[] STATUS_WORD_SUCCESS = { (byte)0x90, (byte)0x00 };

	private final static byte STATUS_CONTINUED = (byte) 97;

	/**
	 * Wraps a response from the card.
	 */
	public static class Response
	{
		public byte[] data;
		public byte[] status;

		private Response(byte[] fullResponse)
		{
			if (fullResponse.length < 2)
			{
				throw new IllegalArgumentException("Response is too short");
			}

			data = Arrays.copyOfRange(fullResponse, 0, fullResponse.length - 2);
			status = Arrays.copyOfRange(fullResponse, fullResponse.length - 2, fullResponse.length);
		}

		/**
		 * Returns true if the status indicates this response is continued.
		 */
		public boolean isStatusContinued()
		{
			return STATUS_CONTINUED == status[0];
		}

		/**
		 * Returns true if the status indicates success.
		 */
		public boolean isStatusSuccess()
		{
			return Arrays.equals(STATUS_WORD_SUCCESS, status);
		}

		/**
		 * Returns true if the wrapped status indicates success.
		 */
		public boolean isWrappedStatusSuccess()
		{
			return Arrays.equals(STATUS_WORD_SUCCESS, Arrays.copyOfRange(data, data.length - 12, data.length - 10));
		}
	}

	/**
	 * Constructor is private - use create().
	 */
	private Transceiver(Logger logger, IsoDep isoDep)
	{
		this.logger = logger;
		this.isoDep = isoDep;
	}

	/**
	 * Creates a transceiver for the specified tag.
	 * @return null is returned if a transceiver could not be created
	 */
	public static Transceiver create(Logger logger, Tag tag)
	{
		IsoDep isoDep = IsoDep.get(tag);
		if (null == isoDep)
		{
			logger.warn(TAG, "Unable to create IsoDep for NFC tag: " + StringUtil.join(tag.getTechList(), ", "));
			return null;
		}

		logger.info(TAG, "Connnecting to ISO-DEP: " + isoDep.isConnected());
		try
		{
			isoDep.connect();
			isoDep.setTimeout(30000);
			return new Transceiver(logger, isoDep);
		}
		catch (Exception ex)
		{
			logger.error(TAG, "Unable to connect to ISO-DEP", ex);
			return null;
		}
	}

	/**
	 * Closes the transceiver, releasing all resources.
	 */
	public void close()
	{
		logger.newLine();

		try
		{
			logger.info(TAG, "Closing ISO-DEP...");
			isoDep.close();
		}
		catch (IOException e)
		{
			logger.warn(TAG, "Error closing ISO-DEP", e);
		}
	}

	/**
	 * Sends the specified data to the tag and returns the complete
	 * response, concatenating continued responses if necessary.
	 *
	 * @param apduType the type of APDU being sent
	 * @param apduData a hex string that is converted to a byte array
	 * @return the complete response; null is returned if the transaction fails
	 */
	public Response transceive(String apduType, String apduData)
	{
		byte[][] apduBytes=new byte[1][];
        apduBytes[0]=ByteUtil.hexStringToByteArray(apduData);
        return transceive(apduType, apduBytes);
	}

    /**
     * Sends the specified data to the tag and returns the complete
     * response, concatenating continued responses if necessary.
     *
     * @param apduType the type of APDU being sent
     * @param apduData a byte array that is converted to an array of byte arrays
     * @return the complete response; null is returned if the transaction fails
     */
    public Response transceive(String apduType, byte[] apduData)
    {
        byte[][] apduBytes = new byte[1][];
        apduBytes[0] = apduData;
        return transceive(apduType, apduBytes);
    }

    /**
     * Sends the specified data to the tag and returns the complete
     * response, concatenating continued responses if necessary.
     *
     * @param apduType the type of APDU being sent
     * @param apduData the APDU data that is being sent
     * @return the complete response; null is returned if the transaction fails
     */
	public Response transceive(String apduType, byte[][] apduData)
	{
		logger.newLine();
		logger.info(TAG, "Sending " + apduType + ": ");
		for(byte[] byt : apduData)
		{
			logger.info(TAG, ByteUtil.toHexString(byt, " ") + "\n");
		}

		byte[] fullResponse;
		try
		{
			long startTime = System.currentTimeMillis();
			Response response = null;

            byte[][] apduBytes=apduData;
            while (null == response || response.isStatusContinued())
			{


                fullResponse = isoDep.transceive(apduBytes[0]);
                Response commStatus=new Response(fullResponse);
                if (apduBytes.length>1 && commStatus.isStatusSuccess())
                {
                    for (int i=1; i<apduBytes.length; i++)
                    {
                        fullResponse = isoDep.transceive(apduBytes[i]);
                    }
                }


                try
                {
                    Response newResponse = new Response(fullResponse);
                    if (null == response)
                    {
                        response = newResponse;
                    } else
                    {
                        response.data = ByteUtil.concatenate(response.data, newResponse.data);
                        response.status = newResponse.status;
                    }
                } catch (Exception ex)
                {
                    logger.warn(TAG, "Unable to parse response: " + ex.getMessage());
                    return null;
                }


				if (!(response.isStatusSuccess() || response.isStatusContinued()))
				{
					logger.warn(TAG, "Response contains unexpected status word: " + ByteUtil.toHexString(response.status));
					return null;
				}

				// If there is more data, build message to send to ask for that data:
				if (response.isStatusContinued())
				{
                    apduBytes=new byte[1][];
					apduBytes[0] = ByteUtil.hexStringToByteArray(String.format("00 C0 00 00 %02x", response.status[1] & 0xff));
				}
			}

			long stopTime = System.currentTimeMillis();
			if(response.data.length > 100)
			{
				logger.info(TAG, apduType + " Response: " + ByteUtil.toHexString(Arrays.copyOfRange(response.data,0,86), " ") + " ... response truncated ... " + ByteUtil.toHexString(Arrays.copyOfRange(response.data,response.data.length-14,response.data.length), " ")+" "+ ByteUtil.toHexString(response.status, " "));
			}
			else
			{
				logger.info(TAG, apduType + " Response: " + ByteUtil.toHexString(response.data, " ") + "  " + ByteUtil.toHexString(response.status, " "));
			}
			logger.info(TAG, "Elapsed time : " + (stopTime - startTime) + " ms");

			return response;
		}
		catch (Exception ex)
		{
			logger.error(TAG, "Unable to send APDU", ex);
			return null;
		}
	}
}
