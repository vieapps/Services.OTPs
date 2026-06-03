using System;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Utility;

namespace net.vieapps.Services.OTPs.Authenticator
{
	public class ServiceComponent : ServiceBase
	{
		public override string ServiceName => "AuthenticatorOTP";

		Cache Cache { get; } = Cache.CreateInstance("VIEApps-Services-AuthenticatorOTP", Components.Utility.Logger.GetLoggerFactory(), "true".IsEquals(UtilityService.GetAppSetting("AuthenticatorOTP:Cache:L1")));

		public override Task StartAsync(string[] args = null, bool initializeRepository = true, Action<IService> next = null)
		{
			this.Syncable = false;
			return base.StartAsync(args, false, this.Cache, next);
		}

		public override Task<JToken> ProcessRequestAsync(RequestInfo requestInfo, CancellationToken cancellationToken = default)
		{
			var stopwatch = Stopwatch.StartNew();
			this.Statistics.RpcEntered();
			this.WriteLogsAsync(requestInfo, $"Begin request ({requestInfo.Verb} {requestInfo.GetURI()})").Execute();
			try
			{
				// check
				if (!requestInfo.Verb.Equals("GET"))
					return Task.FromException<JToken>(new MethodNotAllowedException(requestInfo.Verb));
				else if (requestInfo.Extra == null)
					return Task.FromException<JToken>(new InvalidRequestException());

				// prepare
				var id = requestInfo.Extra.ContainsKey("ID") ? requestInfo.Extra["ID"].Decrypt(this.EncryptionKey) : null;
				var stamp = requestInfo.Extra.ContainsKey("Stamp") ? requestInfo.Extra["Stamp"].Decrypt(this.EncryptionKey) : null;
				if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(stamp))
					return Task.FromException<JToken>(new InvalidRequestException());

				var type = requestInfo.Extra.ContainsKey("Type") ? requestInfo.Extra["Type"] : "App";
				var secret = $"{id}@{stamp}".ToLower().GetHMACSHA512Hash(this.GetKey("Authentication", "VIEApps-65E47754-NGX-50C0-Services-4565-Authentication-BA55-Key-A8CC23879C5D"));
				var otp = OTPService.GeneratePassword(secret, "App".IsEquals(type) ? 30 : Int32.TryParse(UtilityService.GetAppSetting("OTPs:Interval", ""), out var interval) && interval >= 300 ? interval : 900, Int32.TryParse(UtilityService.GetAppSetting("OTPs:Digits", ""), out var digits) && digits > 3 ? digits : 6);

				// provision/setup
				var json = new JObject();
				if (requestInfo.Extra.ContainsKey("Setup"))
				{
					var account = requestInfo.Extra.ContainsKey("Account") ? requestInfo.Extra["Account"].Decrypt(this.EncryptionKey) : "";
					var issuer = requestInfo.Extra.ContainsKey("Issuer") ? requestInfo.Extra["Issuer"].Decrypt(this.EncryptionKey) : "";
					if (string.IsNullOrWhiteSpace(issuer))
						issuer = UtilityService.GetAppSetting("OTPs:Issuer", "VIEApps NGX");
					var provisioningUri = OTPService.GenerateProvisioningUri(account, secret, issuer.UrlEncode());
					var size = requestInfo.Extra.ContainsKey("Size") ? requestInfo.Extra["Size"].CastAs<int>() : UtilityService.GetAppSetting("OTPs:QRCode:Size", "300").CastAs<int>();
					var ecl = requestInfo.Extra.ContainsKey("ECCLevel") ? requestInfo.Extra["ECCLevel"] : UtilityService.GetAppSetting("OTPs:QRCode:ECCLevel", "L");
					json["URI"] = this.GetHttpURI("Files", "https://fs.vieapps.net")
						+ $"/qrcodes/{UtilityService.NewUUID.Encrypt(null, true).Substring(UtilityService.GetRandomNumber(13, 43), 13)}"
						+ $"?v={provisioningUri.Encrypt(this.EncryptionKey).ToBase64Url(true)}"
						+ $"&t={DateTime.Now.ToUnixTimestamp().ToString().Encrypt(this.EncryptionKey).ToBase64Url(true)}"
						+ $"&s={size}&ecl={ecl}";
				}

				// validate OTP
				else if (!otp.IsEquals(requestInfo.Extra.ContainsKey("Password") ? requestInfo.Extra["Password"].Decrypt(this.EncryptionKey) : ""))
					return Task.FromException<JToken>(new OTPLoginFailedException());

				this.WriteLogsAsync(requestInfo, $"Success response - Execution times: {stopwatch.GetElapsedTimes()}").Execute();
				if (this.IsDebugResultsEnabled)
					this.WriteLogsAsync(requestInfo, $"- Request: {requestInfo.ToString(this.JsonFormat)}" + "\r\n" + $"- Response: {json?.ToString(this.JsonFormat)}").Execute();
				return Task.FromResult<JToken>(json);
			}
			catch (Exception ex)
			{
				return Task.FromException<JToken>(this.GetRuntimeException(requestInfo, ex, stopwatch));
			}
			finally
			{
				this.Statistics.RpcCompleted(stopwatch);
			}
		}
	}

	public class OTPLoginFailedException : AppException
	{
		public OTPLoginFailedException() : base("Bad OTP") { }
		public OTPLoginFailedException(string message) : base(message) { }
	}
}