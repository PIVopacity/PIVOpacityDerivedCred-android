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

/**
 * String utilities.
 */
public class StringUtil
{
	private StringUtil()
	{
	}

	/**
	 * Joins an array of strings into one string using the specified joint.
	 */
	public static String join(String[] strings, String joint)
	{
		StringBuilder sb = new StringBuilder();
		for (String s : strings)
		{
			sb.append(s).append(joint);
		}

		if (sb.length() > 0 && joint.length() > 0)
		{
			sb.delete(sb.length() - joint.length(), sb.length() - 1);
		}

		return sb.toString();
	}
}
