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
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Gravity;
import android.widget.TextView;

/**
 * A singleton that provides for standard Android logging
 * and for logging to the device screen.
 */
public class Logger
{
	private Activity activity;
	private TextView logText;

	/**
	 * Construct an instance.
	 * @param activity the activity for which we are logging
	 * @param logText the TextView to use for displaying messages on the device screen
	 */
	public Logger(Activity activity, TextView logText)
	{
		this.activity = activity;
		this.logText = logText;
		logText.setMovementMethod(new ScrollingMovementMethod());
		logText.setGravity(Gravity.BOTTOM);
	}
	public Logger(Activity activity, TextView logText,Boolean scrollLock)
	{
		this.activity = activity;
		this.logText = logText;
		logText.setMovementMethod(new ScrollingMovementMethod());
		if(!scrollLock)
		{
			logText.setGravity(Gravity.BOTTOM);
		}
		else
		{
			logText.setGravity(Gravity.TOP);
		}
	}

	/**
	 * Display an alert in a non-modal pop-up dialog on the device.
	 */
	public void alert(final String alert, final String title)
	{
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				AlertDialog.Builder builder = new AlertDialog.Builder(activity);
				if (null != title)
				{
					builder.setTitle(title);
				}
				builder.setMessage(alert);
				builder.setNeutralButton("OK", null);
				builder.create().show();
			}
		});
	}

	private void displayAppend(final String msg)
	{
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				logText.append(msg + "\n");
			}
		});
	}

	private void displaySet(String msg)
	{
		final String finalMsg = msg + "\n";
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				logText.setText(finalMsg);
			}
		});
	}

	/**
	 * Clears the display on the device.
	 */
	public void clear()
	{
		displaySet("");
	}

	/**
	 * Log a debug message.
	 */
	public void debug(String tag, String msg)
	{
		Log.d(tag, msg);
	}

	/**
	 * Log an error message.
	 */
	public void error(String tag, String msg)
	{
		Log.e(tag, msg);
		displayAppend(msg);
	}

	/**
	 * Log an error message with a Throwable.
	 */
	public void error(String tag, String msg, Throwable tr)
	{
		Log.e(tag, msg, tr);
		displayAppend(msg + ": " + tr.getMessage());
	}

	/**
	 * Log an info message.
	 */
	public void info(String tag, final String msg)
	{
		Log.i(tag, msg);
		displayAppend(msg);
	}

	/**
	 * Log a newline - only applies to the device screen.
	 */
	public void newLine()
	{
		displayAppend("");
	}

	/**
	 * Log a warning message.
	 */
	public void warn(String tag, final String msg)
	{
		Log.w(tag, msg);
		displayAppend(msg);
	}

	/**
	 * Log a warning message with a Throwable.
	 */
	public void warn(String tag, final String msg, final Throwable tr)
	{
		Log.w(tag, msg, tr);
		displayAppend(msg + ": " + tr.getMessage());
	}
}
