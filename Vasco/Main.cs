#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Serialization;

using Newtonsoft.Json.Linq;

using IdentikeyAuthWrapper.vasco.identikey.model;
using IdentikeyAuthWrapper.vasco.identikey.authentication;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.OTPs
{
	public class ServiceComponent : ServiceBase
	{
		public override string ServiceName => "VascoOTP";

		public override void Start(string[] args = null, bool initializeRepository = true, Func<ServiceBase, Task> next = null) => base.Start(args, false, next);

		public override async Task<JToken> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			try
			{
				return requestInfo.Verb.Equals("GET")
					? await UtilityService.ExecuteTask(() => this.ProcessOtpRequest(requestInfo), cancellationToken).ConfigureAwait(false)
					: throw new MethodNotAllowedException(requestInfo.Verb);
			}
			catch (Exception ex)
			{
				throw this.GetRuntimeException(requestInfo, ex);
			}
		}

		JObject ProcessOtpRequest(RequestInfo requestInfo)
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