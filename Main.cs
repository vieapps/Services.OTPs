#region Related components
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;

using IdentikeyAuthWrapper.vasco.identikey.model;
using IdentikeyAuthWrapper.vasco.identikey.authentication;
#endregion

namespace net.vieapps.Services.OTPs
{
	public class ServiceComponent : ServiceBase
	{

		#region Start
		public ServiceComponent() : base() { }

		public override void Start(string[] args = null, bool initializeRepository = true, Func<IService, Task> next = null)
		{
			base.Start(args, false, next);
		}

		internal string AuthenticationKey
		{
			get
			{
				return this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D");
			}
		}

		public override string ServiceName { get { return "OTPs"; } }
		#endregion

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			// check
			if (!requestInfo.Verb.Equals("GET"))
				throw new MethodNotAllowedException(requestInfo.Verb);

			// track
			var stopwatch = new Stopwatch();
			stopwatch.Start();
			var logs = new List<string>() { $"Begin process ({requestInfo.Verb}): {requestInfo.URI}" };
#if DEBUG || REQUESTLOGS
			logs.Add($"Request:\r\n{requestInfo.ToJson().ToString(Formatting.Indented)}");
#endif
			await this.WriteLogsAsync(requestInfo.CorrelationID, logs).ConfigureAwait(false);

			// process
			try
			{
				switch (requestInfo.ObjectName.Trim().ToLower())
				{
					case "authenticator":
						return await this.ProcessAuthenticatorOtpRequestAsync(requestInfo, cancellationToken).ConfigureAwait(false);

					case "vasco":
						return await UtilityService.ExecuteTask(() => this.ProcessVascoOtpRequest(requestInfo), cancellationToken).ConfigureAwait(false);

					default:
						throw new InvalidRequestException($"The request is invalid [({requestInfo.Verb}): {requestInfo.URI}]");
				}
			}
			catch (Exception ex)
			{
				await this.WriteLogAsync(requestInfo.CorrelationID, "Error occurred while processing", ex).ConfigureAwait(false);
				throw this.GetRuntimeException(requestInfo, ex);
			}
			finally
			{
				stopwatch.Stop();
				await this.WriteLogAsync(requestInfo.CorrelationID, $"End process - Execution times: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);
			}
		}

		#region Process one-time password of Authenticator
		async Task<JObject> ProcessAuthenticatorOtpRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			// check
			if (requestInfo.Extra == null)
				throw new InvalidRequestException();

			// prepare
			var id = requestInfo.Extra.ContainsKey("ID") ? requestInfo.Extra["ID"].Decrypt(this.EncryptionKey) : "";
			var stamp = requestInfo.Extra.ContainsKey("Stamp") ? requestInfo.Extra["Stamp"].Decrypt(this.EncryptionKey) : "";

			var key = (id + "@" + stamp).ToLower().GetHMACHash(this.AuthenticationKey.ToBytes(), "SHA512");
			var response = new JObject();

			// setup for provisioning
			if (requestInfo.Extra.ContainsKey("Setup"))
			{
				var account = requestInfo.Extra.ContainsKey("Account") ? requestInfo.Extra["Account"].Decrypt(this.EncryptionKey) : "";
				var issuer = requestInfo.Extra.ContainsKey("Issuer") ? requestInfo.Extra["Issuer"].Decrypt(this.EncryptionKey) : null;
				var size = requestInfo.Extra.ContainsKey("Size") ? requestInfo.Extra["Size"].CastAs<int>() : 300;
				var provisioning = await OTPService.GenerateProvisioningImageAsync(account, key, issuer, size).ConfigureAwait(false);
				var imageUri = this.GetHttpURI("Files", "https://afs.vieapps.net")
					+ "/otps/" + UtilityService.NewUID.Encrypt().ToHexa(true).Substring(UtilityService.GetRandomNumber(13, 43), 13)
					+ "?v=" + CryptoService.Encrypt(CacheUtils.Helper.Combine(BitConverter.GetBytes(DateTime.Now.ToUnixTimestamp()), provisioning), this.EncryptionKey.GenerateEncryptionKey(), this.EncryptionKey.GenerateEncryptionIV()).ToBase64Url();
				response = new JObject()
				{
					{ "Uri", imageUri }
				};
			}

			// validate input of client
			else
			{
				var password = requestInfo.Extra.ContainsKey("Password") ? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey) : "";
				if (string.IsNullOrWhiteSpace(password))
					throw new OTPLoginFailedException();

				var interval = (requestInfo.Extra.ContainsKey("Type") ? requestInfo.Extra["Type"] : "App").IsEquals("SMS") ? 300 : 30;
				if (!password.Equals(OTPService.GeneratePassword(key, interval)))
					throw new OTPLoginFailedException();
			}

			// response
			return response;
		}
		#endregion

		#region Process one-time-password of VASCO Identity
		JObject ProcessVascoOtpRequest(RequestInfo requestInfo)
		{
			// prepare
			var domain = "";
			var account = "";
			var otp = "";

			if (requestInfo.Extra != null)
			{
				domain = requestInfo.Extra.ContainsKey("Domain")
					? requestInfo.Extra["Domain"]
					: "";
				account = requestInfo.Extra.ContainsKey("Account")
					? requestInfo.Extra["Account"]
					: "";
				otp = requestInfo.Extra.ContainsKey("OTP")
					? requestInfo.Extra["OTP"]
					: "";
			}

			if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(account) || string.IsNullOrWhiteSpace(otp))
				throw new OTPLoginFailedException();

			// authenticate via VASCO wrapper services
			var results = new AuthenticationHandler().authUser(domain, account, "", otp, "", CredentialsBase.RequestHostCode.Optional);

			// if return code is not equal to zero, means error occured while signing-in
			var resultCode = results.getReturnCode().ToString();
			var statusCode = results.getStatusCode().ToString();
			if (!resultCode.Equals("0"))
			{
				// get error details
				var errorStack = results.getErrorStack();
				var error = errorStack.Count > 0
					? errorStack[0]
					: null;

				var errorDetails = "";
				if (error != null)
					errorDetails = "Details: " + error.ErrorMessage;

				// login failed
				if (resultCode.Equals("1"))
					throw new OTPLoginFailedException();

				// login failed with details error
				else if (resultCode.Equals("-2"))
				{
					// account is not found
					if (statusCode.Equals("1010"))
						throw new OTPNotFoundException();

					// account is locked
					else if (statusCode.Equals("1007"))
						throw new OTPLockedException();

					// account is disabled
					else if (statusCode.Equals("1009"))
						throw new OTPDisabledException();

					// invalid OTP password
					else if (statusCode.Equals("1012"))
						throw new OTPLoginFailedException();

					// unknown
					else
						throw new OTPLoginFailedException("Failed. Unknown error: " + errorDetails);
				}
				else
					throw new OTPUnknownException("Unknown error: " + errorDetails);
			}

			return new JObject();
		}
		#endregion

		#region Process inter-communicate message
		protected override void ProcessInterCommunicateMessage(CommunicateMessage message)
		{
		}
		#endregion

	}

	#region Exceptions
	[Serializable]
	public class OTPNotFoundException : AppException
	{
		public OTPNotFoundException() : base("OTP account is not found") { }
		public OTPNotFoundException(string message) : base(message) { }
		public OTPNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class OTPLoginFailedException : AppException
	{
		public OTPLoginFailedException() : base("Bad OTP username or password") { }
		public OTPLoginFailedException(string message) : base(message) { }
		public OTPLoginFailedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class OTPExpiredException : AppException
	{
		public OTPExpiredException() : base("OTP token is expired.") { }
		public OTPExpiredException(string message) : base(message) { }
		public OTPExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class OTPLockedException : AppException
	{
		public OTPLockedException() : base("OTP token is locked.") { }
		public OTPLockedException(string message) : base(message) { }
		public OTPLockedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class OTPDisabledException : AppException
	{
		public OTPDisabledException() : base("OTP token is disabled.") { }
		public OTPDisabledException(string message) : base(message) { }
		public OTPDisabledException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class OTPUnknownException : AppException
	{
		public OTPUnknownException() : base("Unknown OTP error!") { }
		public OTPUnknownException(string message) : base(message) { }
		public OTPUnknownException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}
	#endregion

}