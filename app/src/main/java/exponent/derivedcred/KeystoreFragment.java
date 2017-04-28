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

import android.os.Bundle;
import android.os.Environment;
import android.support.v4.app.Fragment;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import exponent.derivedcred.dhsdemo.Logger;


public class KeystoreFragment extends Fragment
{
    private final static String TAG = "KeystoreFragment";

    private ArrayList<String> ksList = new ArrayList<>();
    private KeyStore ks=null;

    private Spinner spinner;
    private ArrayAdapter<String> adapter;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
    {
        View v = inflater.inflate(R.layout.fragment_keystore, container, false);

        spinner = (Spinner) v.findViewById(R.id.spinner);

        TextView logText = (TextView) v.findViewById(R.id.certView);
        final Logger certLogger = new Logger(MainActivity.mainActivity, logText,Boolean.TRUE);


        Button refreshButton = (Button) v.findViewById(R.id.refresh);
        refreshButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                ksList=new ArrayList<>();

                try
                {
                    ks = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e)
                {
                    e.printStackTrace();
                }

                File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PIV_Auth_KeyStore");
                Enumeration<String> aliases = null;

                try
                {
                    if(!file.exists())
                    {
                        certLogger.clear();
                        certLogger.info(TAG,"Keystore Empty! Derive new credential.");
                    } else
                    {
                        ks.load(new FileInputStream(file),null);
                        aliases = ks.aliases();
                        while(aliases.hasMoreElements())
                        {
                            ksList.add(aliases.nextElement());
                        }

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
                } catch (KeyStoreException e)
                {
                    e.printStackTrace();
                }

                // Create an ArrayAdapter using the string array and a default spinner layout
                adapter = new ArrayAdapter<String>(getContext(), R.layout.spinner_item_custom, ksList);
                // Specify the layout to use when the list of choices appears
                adapter.setDropDownViewResource(R.layout.spinner_drop_menu_custom);
                // Apply the adapter to the spinner
                spinner.setAdapter(adapter);
            }
        });

        Button clearButton = (Button) v.findViewById(R.id.clearKs);
        clearButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                try
                {
                    ks = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e)
                {
                    e.printStackTrace();
                }

                File file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "PIV_Auth_KeyStore");

                try
                {
                    ks.load(new FileInputStream(file),null);
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
                    ks = KeyStore.getInstance("AndroidKeyStore");
                    ks.load(null);
                    ks.deleteEntry("derivedPivKey");
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


                if(!ksList.isEmpty())
                {
                    ksList.clear();
                    // Create an ArrayAdapter using the string array and a default spinner layout
                    adapter = new ArrayAdapter<String>(getContext(), R.layout.spinner_item_custom, ksList);
                    // Specify the layout to use when the list of choices appears
                    adapter.setDropDownViewResource(R.layout.spinner_drop_menu_custom);
                    // Apply the adapter to the spinner
                    spinner.setAdapter(adapter);
                    spinner.setGravity(Gravity.START);
                }
                if(file.exists())
                {
                    file.delete();
                }

                certLogger.clear();
                certLogger.info(TAG,"\t\tKeystore Cleared!");
            }
        });

        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {

                if(null!=ks)
                {
                    try
                    {
                        certLogger.clear();
                        certLogger.info(TAG, ks.getCertificate(parent.getItemAtPosition(pos).toString()).toString());
                    } catch (KeyStoreException e)
                    {
                        e.printStackTrace();
                    }
                }

            }

            @Override
            public void onNothingSelected(AdapterView<?> parent)
            {

            }
        });


        return v;
    }


}
