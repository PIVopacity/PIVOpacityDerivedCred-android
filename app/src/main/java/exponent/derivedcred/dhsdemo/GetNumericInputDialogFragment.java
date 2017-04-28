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
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

import java.util.concurrent.Semaphore;

import exponent.derivedcred.R;


/**
 * Dialog fragment for obtaining numeric input from the user.
 * The dialog is implemented as a modal dialog.
 */
public class GetNumericInputDialogFragment extends DialogFragment
{
	private String input;
	private final Semaphore dialogSemaphore = new Semaphore(0, true);

	public static GetNumericInputDialogFragment create(String title)
	{
		GetNumericInputDialogFragment frag = new GetNumericInputDialogFragment();
		Bundle args = new Bundle();
		args.putCharSequence("title", title);
		frag.setArguments(args);
		return frag;
	}

	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState)
	{
		AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());

		//noinspection ConstantConditions
		builder.setTitle(getArguments().get("title").toString());
		builder.setCancelable(false);
		LayoutInflater inflater = getActivity().getLayoutInflater();
		final View dialogLayout = inflater.inflate(R.layout.dialog_get_numeric_input, null);
		builder.setView(dialogLayout);
		builder.setPositiveButton("OK", new DialogInterface.OnClickListener()
		{
			@Override
			public void onClick(DialogInterface dialog, int id)
			{
				TextView tv = (TextView) dialogLayout.findViewById(R.id.numericPassword);
				input = tv.getText().toString();
				dialogSemaphore.release();
			}
		});

		Dialog dialog = builder.create();
		dialog.setCancelable(false);
		dialog.setCanceledOnTouchOutside(false);
		return dialog;
	}

	/**
	 * Displays the modal dialog and returns the characters entered by the user.
	 */
	public String showDialog(Activity activity)
	{
		show(activity.getFragmentManager(),"numericPassword");

		try
		{
			dialogSemaphore.acquire();
		}
		catch (InterruptedException ex)
		{
			//ignore
		}

		return input;
	}

}