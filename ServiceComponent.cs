#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.Serialization;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;

using IdentikeyAuthWrapper.vasco.identikey.model;
using IdentikeyAuthWrapper.vasco.identikey.authentication;
#endregion

namespace net.vieapps.Services.OTPs
{
	public class ServiceComponent : BaseService
	{

		#region Start
		public ServiceComponent() { }

		void WriteInfo(string correlationID, string info, Exception ex = null, bool writeLogs = true)
		{
			// prepare
			var msg = string.IsNullOrWhiteSpace(info)
				? ex?.Message ?? ""
				: info;

			// write to logs
			if (writeLogs)
				this.WriteLog(correlationID ?? UtilityService.NewUID, this.ServiceName, null, msg, ex);

			// write to console
			if (!Program.AsService)
			{
				Console.WriteLine(msg);
				if (ex != null)
					Console.WriteLine("-----------------------\r\n" + "==> [" + ex.GetType().GetTypeName(true) + "]: " + ex.Message + "\r\n" + ex.StackTrace + "\r\n-----------------------");
				else
					Console.WriteLine("~~~~~~~~~~~~~~~~~~~~>");
			}
		}

		internal void Start(string[] args = null, System.Action nextAction = null, Func<Task> nextActionAsync = null)
		{
			// prepare
			var correlationID = UtilityService.NewUID;

			// start the service
			Task.Run(async () =>
			{
				try
				{
					await this.StartAsync(
						service => this.WriteInfo(correlationID, "The service is registered - PID: " + Process.GetCurrentProcess().Id.ToString()),
						exception => this.WriteInfo(correlationID, "Error occurred while registering the service", exception)
					);
				}
				catch (Exception ex)
				{
					this.WriteInfo(correlationID, "Error occurred while starting the service", ex);
				}
			})
			.ContinueWith(async (task) =>
			{
				try
				{
					nextAction?.Invoke();
				}
				catch (Exception ex)
				{
					this.WriteInfo(correlationID, "Error occurred while running the next action (sync)", ex);
				}
				if (nextActionAsync != null)
					try
					{
						await nextActionAsync().ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						this.WriteInfo(correlationID, "Error occurred while running the next action (async)", ex);
					}
			})
			.ConfigureAwait(false);
		}
		#endregion

		public override string ServiceName { get { return "otps"; } }

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
#if DEBUG
			this.WriteInfo(requestInfo.CorrelationID, "Process the request\r\n==> Request:\r\n" + requestInfo.ToJson().ToString(Formatting.Indented), null, false);
#endif
			try
			{
				switch (requestInfo.ObjectName.Trim().ToLower())
				{
					case "vasco":
						return await this.ProcessVascoOtpAsync(requestInfo, cancellationToken);
				}

				// unknown
				var msg = "The request is invalid [" + this.ServiceURI + "]: " + requestInfo.Verb + " /";
				if (!string.IsNullOrWhiteSpace(requestInfo.ObjectName))
					msg +=  requestInfo.ObjectName + (!string.IsNullOrWhiteSpace(requestInfo.GetObjectIdentity()) ? "/" + requestInfo.GetObjectIdentity() : "");
				throw new InvalidRequestException(msg);
			}
			catch (Exception ex)
			{
				this.WriteInfo(requestInfo.CorrelationID, "Error occurred while processing\r\n==> Request:\r\n" + requestInfo.ToJson().ToString(Formatting.Indented), ex);
				throw this.GetRuntimeException(requestInfo, ex);
			} 
		}

		#region Process VASCO one-time-password
		Task<JObject> ProcessVascoOtpAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
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

			try
			{
				// authenticate via VASCO wrapper services
				var results = (new AuthenticationHandler()).authUser(domain, account, "", password, "", CredentialsBase.RequestHostCode.Optional);

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

				return Task.FromResult(new JObject()
				{
				});
			}
			catch (Exception ex)
			{
				return Task.FromException<JObject>(ex);
			}
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