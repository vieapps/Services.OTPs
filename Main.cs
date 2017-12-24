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
		public ServiceComponent() : base() { }

		public override void Start(string[] args = null, bool initializeRepository = true, Func<IService, Task> next = null)
		{
			base.Start(args, false, next);
		}

		public override string ServiceName { get { return "OTPs"; } }

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			// track
			var stopwatch = new Stopwatch();
			stopwatch.Start();
			var uri = $"[{requestInfo.Verb}]: /{this.ServiceName}";
			if (!string.IsNullOrWhiteSpace(requestInfo.ObjectName))
				uri += requestInfo.ObjectName + "/" + (requestInfo.GetObjectIdentity() ?? "");
			var logs = new List<string>() { $"Process the request {uri}" };
#if DEBUG || REQUESTLOGS
			logs.Add($"Request ==> {requestInfo.ToJson().ToString(Formatting.Indented)}");
#endif
			await this.WriteLogsAsync(requestInfo.CorrelationID, logs).ConfigureAwait(false);

			// process
			try
			{
				switch (requestInfo.ObjectName.Trim().ToLower())
				{
					case "vasco":
						return await UtilityService.ExecuteTask(() => this.ProcessVascoOtpRequest(requestInfo), cancellationToken).ConfigureAwait(false);
				}
				throw new InvalidRequestException("The request is invalid [" + this.ServiceURI + "]: " + uri);
			}
			catch (Exception ex)
			{
				await this.WriteLogAsync(requestInfo.CorrelationID, "Error occurred while processing", ex).ConfigureAwait(false);
				throw this.GetRuntimeException(requestInfo, ex);
			}
			finally
			{
				stopwatch.Stop();
				await this.WriteLogAsync(requestInfo.CorrelationID, $"The request is completed - Execution times: {stopwatch.GetElapsedTimes()}").ConfigureAwait(false);
			}
		}

		#region Process VASCO one-time-password
		JObject ProcessVascoOtpRequest(RequestInfo requestInfo)
		{
			var domain = "";
			var account = "";
			var password = "";

			if (requestInfo.Extra != null)
			{
				domain = requestInfo.Extra.ContainsKey("Domain")
					? requestInfo.Extra["Domain"]
					: "";
				account = requestInfo.Extra.ContainsKey("Account")
					? requestInfo.Extra["Account"]
					: "";
				password = requestInfo.Extra.ContainsKey("Password")
					? requestInfo.Extra["Password"]
					: "";
			}

			// authenticate via VASCO wrapper services
			var results = new AuthenticationHandler().authUser(domain, account, "", password, "", CredentialsBase.RequestHostCode.Optional);

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

			return new JObject()
			{
				{"Status", "OK" }
			};
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