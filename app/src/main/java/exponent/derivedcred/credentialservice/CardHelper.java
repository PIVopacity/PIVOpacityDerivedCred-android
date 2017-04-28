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

import android.util.Log;
import java.util.Arrays;
import exponent.derivedcred.dhsdemo.ByteUtil;
import exponent.derivedcred.opacity.Opacity;

public class CardHelper
{
    private String TAG="Card Helper: ";
    private byte[] resp=null;
    private int start=0;
    private int stop=0;
    private byte[] lcomm=null;


    public void SetLongResponse(byte [] lresp)
    {
        clearLongResponse();
        resp=lresp;
    }


    public void SetLongResponse(String lsrsp)
    {
        SetLongResponse(ByteUtil.hexStringToByteArray(lsrsp));
    }

    public byte[] GetLongResponse(byte[] request)
    {
        start=stop;
        if(request==null)
        {
            start=0;
            stop=255;
        } else
        {
            Byte b= request[request.length-1];
            Log.i(TAG,String.valueOf(((int)b & 0xFF)));
            stop=start+((int)b & 0xFF);
        }


        if(stop>=resp.length)
        {
            return ByteUtil.concatenate(Arrays.copyOfRange(resp, start,resp.length),
                    ByteUtil.hexStringToByteArray("9000"));
        } else
        {
            int remain=resp.length-stop;
            if (remain > 255)
            {
                remain=255;
            }

            return ByteUtil.concatenate(Arrays.copyOfRange(resp, start, stop),
                    ByteUtil.hexStringToByteArray(String.format("61%02X", remain)));
        }
    }

    public boolean setLongCommand(byte[] comm)
    {
        if(((int)comm[0]&0xF0)==0x10)
        {
            lcomm=ByteUtil.concatenate(lcomm,Arrays.copyOfRange(comm,5,5+((int)comm[4]&0xFF)));
            return true;
        } else if(((int)comm[0]&0xF0)==0x00)
        {
            lcomm=ByteUtil.concatenate(lcomm,Arrays.copyOfRange(comm,5,5+((int)comm[4]&0xFF)));
            //lcomm=ByteUtil.concatenate(Arrays.copyOf(comm,4), Opacity.berTlvEncodeLen(lcomm.length-13),lcomm);
            lcomm=ByteUtil.concatenate(Arrays.copyOf(comm,4), Opacity.berTlvEncodeLen(lcomm.length-13),lcomm, new byte[] {(byte)0x00});
            return false;
        }
        return false;
    }

    public byte[] getLongCommand()
    {
        return lcomm;
    }

    public void clearLongResponse(){
        start=0;
        stop=0;
        resp=null;
    }

    public void clearLongCommand()
    {
        lcomm=null;
    }



}
