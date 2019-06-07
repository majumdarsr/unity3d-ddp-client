/*
   The MIT License (MIT)

   Copyright (c) 2016 Vincent Cantin (user "green-coder" on Github.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
 */

using UnityEngine;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections;

namespace Moulin.DDP {

public class DdpAccount {

	private DdpConnection connection;

	public delegate void OnLoggedInDelegate(DdpAccount account);
	public delegate void OnLoginErrorDelegate(DdpAccount account, DdpError error);
	public delegate void OnLoggedOutDelegate(DdpAccount account);
	public event OnLoggedInDelegate OnLoggedIn;
	public event OnLoginErrorDelegate OnLoginError;
	public event OnLoggedOutDelegate OnLoggedOut;

	public bool isLogged;
	public string userId;
	public string token;
	public DateTime tokenExpiration;

	public DdpError error;

	public DdpAccount(DdpConnection connection) {
		this.connection = connection;
	}

	public string GetDigest(string password) {
		string digest = BitConverter.ToString(
			new SHA256Managed().ComputeHash(Encoding.UTF8.GetBytes(password)))
		                .Replace("-", "").ToLower();
		return digest;
	}
	private JSONObject GetPasswordObj(string password) {
		string digest = GetDigest(password);
		JSONObject passwordObj = GetDigestObj(digest);
		return passwordObj;
	}
	private JSONObject GetDigestObj(string digest) {
		JSONObject digestObj = JSONObject.Create();
		digestObj.AddField("digest", digest);
		digestObj.AddField("algorithm", "sha-256");
		return digestObj;
	}

	private void HandleLoginResult(MethodCall loginCall) {
		error = loginCall.error;

		if (error == null) {
			JSONObject result = loginCall.result;
			isLogged = true;
			this.userId = result["id"].str;
			this.token = result["token"].str;
			this.tokenExpiration = result["tokenExpires"].GetDateTime();
			if (OnLoggedIn != null) {
				OnLoggedIn(this);
			}
		} else {
			if (OnLoginError != null) {
				OnLoginError(this, error);
			}
		}
	}

	private void HandleLogoutResult(MethodCall logoutCall) {
		error = logoutCall.error;

		if (error == null) {
			isLogged = false;
			this.userId = null;
			this.token = null;
			this.tokenExpiration = default(DateTime);
			if (OnLoggedOut != null) {
				OnLoggedOut(this);
			}
		}
	}
	public IEnumerator CreateUserAndLogin(string username, string password) {
		JSONObject loginPasswordObj = JSONObject.Create();
		loginPasswordObj.AddField("username", username);
		loginPasswordObj.AddField("password", GetPasswordObj(password));

		MethodCall loginCall = connection.Call("createUser", loginPasswordObj);
		yield return loginCall.WaitForResult();
		HandleLoginResult(loginCall);
	}

	public IEnumerator CreateUserAndLogin(string username, string email, string password) {
		JSONObject loginPasswordObj = JSONObject.Create();
		loginPasswordObj.AddField("username", username);
		loginPasswordObj.AddField("email", email);
		loginPasswordObj.AddField("password", GetPasswordObj(password));

		MethodCall loginCall = connection.Call("createUser", loginPasswordObj);
		yield return loginCall.WaitForResult();
		HandleLoginResult(loginCall);
	}

	public IEnumerator Login(string username, string password) {
		JSONObject userObj = JSONObject.Create();
		userObj.AddField("username", username);

		JSONObject loginPasswordObj = JSONObject.Create();
		loginPasswordObj.AddField("user", userObj);
		loginPasswordObj.AddField("password", GetPasswordObj(password));

		MethodCall loginCall = connection.Call("login", loginPasswordObj);
		yield return loginCall.WaitForResult();
		HandleLoginResult(loginCall);
	}

	public IEnumerator LoginWithDigest(string username, string digest) {
		JSONObject userObj = JSONObject.Create();
		userObj.AddField("username", username);

		JSONObject loginPasswordObj = JSONObject.Create();
		loginPasswordObj.AddField("user", userObj);
		loginPasswordObj.AddField("password", GetDigestObj(digest));

		MethodCall loginCall = connection.Call("login", loginPasswordObj);
		yield return loginCall.WaitForResult();
		HandleLoginResult(loginCall);
	}

	public IEnumerator ResumeSession(string token) {
		JSONObject tokenObj = JSONObject.Create();
		tokenObj.AddField("resume", token);

		MethodCall loginCall = connection.Call("login", tokenObj);
		yield return loginCall.WaitForResult();
		HandleLoginResult(loginCall);
	}

	public IEnumerator Logout() {
		MethodCall logoutCall = connection.Call("logout");
		yield return logoutCall.WaitForResult();
		HandleLogoutResult(logoutCall);
	}

}

}
