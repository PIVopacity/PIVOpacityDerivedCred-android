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

package exponent.derivedcred;

import android.nfc.NfcAdapter;
import android.os.Environment;
import android.support.v4.app.Fragment;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import java.io.File;
import java.util.ArrayList;
import exponent.derivedcred.dhsdemo.DeriveCred;
import exponent.derivedcred.dhsdemo.Logger;
import exponent.derivedcred.opacity.Opacity;
import static exponent.derivedcred.MainActivity.logger;


public class CertFragment extends Fragment
{
    private final static String TAG = "CertFragment";
    private final static int NFC_READER_FLAGS = NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
    private int daysValid;
    private String encryptionFlavor;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
    {
        View v = inflater.inflate(R.layout.fragment_cert, container, false);

        TextView logText = (TextView) v.findViewById(R.id.logText);
        MainActivity.logger = new Logger(MainActivity.mainActivity, logText);
        Opacity.logger = MainActivity.logger;

        Button derivebutton = (Button) v.findViewById(R.id.deriveKeys);

        derivebutton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                MainActivity.deriveCred = new DeriveCred(MainActivity.mainActivity, logger, daysValid, encryptionFlavor);

                Log.d(TAG, "Enabling reader mode");
                NfcAdapter nfc = NfcAdapter.getDefaultAdapter(MainActivity.mainActivity);
                if (nfc != null)
                {
                    // Turn on the NFC reader, registering our DeriveCred as the callback:
                    nfc.enableReaderMode(MainActivity.mainActivity, MainActivity.deriveCred, NFC_READER_FLAGS, null);
                }
            }
        });

        Button clearbutton = (Button) v.findViewById(R.id.clearLog);

        clearbutton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                MainActivity.logger.clear();
            }
        });

        Button clearDownloadButton = (Button) v.findViewById(R.id.clearDownloads);
        clearDownloadButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                for( File child : new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),"").listFiles())
                {
                 child.delete();
                }
            }
        });


        final Integer[] days={1,3,7,15,30};
        ArrayList<String> daysList= new ArrayList<String>();
        for(Integer each : days)
        {
            daysList.add(each.toString());
        }

        Spinner spinner = (Spinner) v.findViewById(R.id.spinner2);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(getContext(), R.layout.spinner_item_custom, daysList);
        // Specify the layout to use when the list of choices appears
        adapter.setDropDownViewResource(R.layout.spinner_drop_menu_custom_num);
        // Apply the adapter to the spinner
        spinner.setAdapter(adapter);
        spinner.setSelection(1);

        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id)
            {
                daysValid=days[pos];
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent)
            {

            }
        });

        final ArrayList<String> encryptionFlavorList=new ArrayList<String>();
        encryptionFlavorList.add("ECC prime256v1");
        encryptionFlavorList.add("ECC secp384r1");
        encryptionFlavorList.add("ECC secp521r1");
        encryptionFlavorList.add("RSA 2048");
        encryptionFlavorList.add("RSA 3072");
        encryptionFlavorList.add("RSA 4096");
        //encryptionFlavorList.add("RSA 6144"); //Not Supported by default in AKS
        //encryptionFlavorList.add("RSA 8192"); //Not Supported by default in AKS
        //encryptionFlavorList.add("RSA 10240"); //Not Supported in AKS at all


        Spinner spinner3 = (Spinner) v.findViewById(R.id.spinner3);
        ArrayAdapter<String> adapter3 = new ArrayAdapter<String>(getContext(), R.layout.spinner_item_custom, encryptionFlavorList);
        // Specify the layout to use when the list of choices appears
        adapter3.setDropDownViewResource(R.layout.spinner_drop_menu_custom);
        // Apply the adapter to the spinner
        spinner3.setAdapter(adapter3);
        spinner3.setSelection(1);

        spinner3.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id)
            {
                encryptionFlavor=encryptionFlavorList.get(pos);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent)
            {

            }
        });

        return v;
    }

 }
