#region Related components
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Serialization;

using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.OTPs
{
	public class ServiceComponent : ServiceBase
	{
		public ServiceComponent() : base() { }

		internal string AuthenticationKey => this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D");

		public override string ServiceName => "AuthenticatorOTP";

		public override void Start(string[] args = null, bool initializeRepository = true, Func<ServiceBase, Task> nextAsync = null) => base.Start(args, false, nextAsync);

		public override async Task<JObject> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
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

		JObject ProcessOtpRequest(RequestInfo requestInfo, CancellationToken cancellationToken = default(CancellationToken))
		{
			// check
			if (requestInfo.Extra == null)
				throw new InvalidRequestException();

			// prepare
			var id = requestInfo.Extra.ContainsKey("ID") ? requestInfo.Extra["ID"].Decrypt(this.EncryptionKey) : "";
			var stamp = requestInfo.Extra.ContainsKey("Stamp") ? requestInfo.Extra["Stamp"].Decrypt(this.EncryptionKey) : "";

			var key = $"{id}@{stamp}".ToLower().GetHMACHash(this.AuthenticationKey.ToBytes(), "SHA512");
			var response = new JObject();

			// setup for provisioning
			if (requestInfo.Extra.ContainsKey("Setup"))
			{
				var account = requestInfo.Extra.ContainsKey("Account") ? requestInfo.Extra["Account"].Decrypt(this.EncryptionKey) : "";
				var issuer = requestInfo.Extra.ContainsKey("Issuer") ? requestInfo.Extra["Issuer"].Decrypt(this.EncryptionKey) : "";
				if (string.IsNullOrWhiteSpace(issuer))
					issuer = UtilityService.GetAppSetting("OTPs:Issuer", "VIEApps NGX");
				var size = requestInfo.Extra.ContainsKey("Size") ? requestInfo.Extra["Size"].CastAs<int>() : UtilityService.GetAppSetting("OTPs:QRCode-Size", "300").CastAs<int>();
				var ecl = requestInfo.Extra.ContainsKey("ECCLevel") ? requestInfo.Extra["ECCLevel"] : UtilityService.GetAppSetting("OTPs:QRCode-ECCLevel", "L");
				var provisioningUri = OTPService.GenerateProvisioningUri(account, key, issuer.UrlEncode());

				response["Uri"] = this.GetHttpURI("Files", "https://afs.vieapps.net")
					+ "/qrcodes/" + UtilityService.NewUUID.Encrypt(null, true).Substring(UtilityService.GetRandomNumber(13, 43), 13)
					+ "?v=" + provisioningUri.Encrypt(this.EncryptionKey).ToBase64Url(true)
					+ "&t=" + DateTime.Now.ToUnixTimestamp().ToString().Encrypt(this.EncryptionKey).ToBase64Url(true)
					+ "&s=" + size + "&ecl=" + ecl;
			}

			// validate input of client
			else
			{
				var password = requestInfo.Extra.ContainsKey("Password") ? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey) : "";
				if (string.IsNullOrWhiteSpace(password))
					throw new OTPLoginFailedException();

				var interval = "App".IsEquals(requestInfo.Extra.ContainsKey("Type") ? requestInfo.Extra["Type"] : "App") ? 30 : 300;
				if (!password.Equals(OTPService.GeneratePassword(key, interval)))
					throw new OTPLoginFailedException();
			}

			// response
			return response;
		}
	}

	[Serializable]
	public class OTPLoginFailedException : AppException
	{
		public OTPLoginFailedException() : base("Bad OTP") { }
		public OTPLoginFailedException(string message) : base(message) { }
		public OTPLoginFailedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}
}