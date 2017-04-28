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

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;
import exponent.derivedcred.credentialservice.CredCardService;
import exponent.derivedcred.dhsdemo.Logger;


public class PACSFragment extends Fragment
{

    public static String opacityTag;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
    {
        final View v = inflater.inflate(R.layout.fragment_pacs, container, false);

        TextView pacsLogText = (TextView) v.findViewById(R.id.pacsLogText);

        CredCardService.logger = new Logger(MainActivity.mainActivity, pacsLogText);

        Button clearbutton = (Button) v.findViewById(R.id.pacsClearLog);

        final RadioGroup opacRadio=(RadioGroup) v.findViewById(R.id.radioOpacity);

        clearbutton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                CredCardService.logger.clear();
            }
        });



        RadioButton opac128Button=(RadioButton) v.findViewById(R.id.radio128);
        RadioButton opac192Button=(RadioButton) v.findViewById(R.id.radio192);
        if(CredCardService.opacityTag.equals("2E"))
        {
            opac128Button.setChecked(false);
            opac192Button.setChecked(true);
        }
        else
        {
            opac128Button.setChecked(true);
            opac192Button.setChecked(false);
        }

        final RadioButton[] opacityRadioButton = new RadioButton[1];
        Button opacResetButton = (Button) v.findViewById(R.id.opacButton);
        opacResetButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View arg0)
            {
                MainActivity.mainActivity.stopService(new Intent(MainActivity.mainActivity,CredCardService.class));
                opacityRadioButton[0] = (RadioButton) v.findViewById(opacRadio.getCheckedRadioButtonId());
                opacityTag = (String) opacityRadioButton[0].getText();
                if(opacityTag.startsWith("192"))
                {
                    opacityTag="2E";
                }
                else
                {
                    opacityTag="27";
                }
                CredCardService.logger.clear();
                Toast.makeText(MainActivity.mainActivity,"Credential Service Restarting",Toast.LENGTH_SHORT).show();
                MainActivity.mainActivity.startService(new Intent(MainActivity.mainActivity,CredCardService.class));
            }
        });


        return v;

    }
}
