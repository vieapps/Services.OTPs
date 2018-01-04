#region Related components
using System;
using System.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading.Tasks;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.OTPs
{
	public class Authenticator
	{
		static string UrlEncodeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
		static string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		static int InByteSize = 8;
		static int OutByteSize = 5;
		static int SizeOfInt32 = 4;
		static int Modulo = (int)Math.Pow(10, 6);

		/// <summary>
		/// Generates the one-time password
		/// </summary>
		/// <param name="secret"></param>
		/// <returns></returns>
		public static string GenerateOTP(byte[] secret)
		{
			var bytes = BitConverter.GetBytes((long)Math.Floor((DateTime.UtcNow - DateTimeService.UnixEpoch).TotalSeconds) / 30);
			if (BitConverter.IsLittleEndian)
				Array.Reverse(bytes);

			var hash = new HMACSHA1(secret).ComputeHash(bytes);
			bytes = new byte[Authenticator.SizeOfInt32];
			Buffer.BlockCopy(hash, hash[hash.Length - 1] & 0xF, bytes, 0, Authenticator.SizeOfInt32);
			if (BitConverter.IsLittleEndian)
				Array.Reverse(bytes);

			return ((BitConverter.ToInt32(bytes, 0) & 0x7FFFFFFF) % Authenticator.Modulo).ToString(CultureInfo.InvariantCulture).PadLeft(6, '0');
		}

		/// <summary>
		/// Generates the QR code bitmap for provisioning
		/// </summary>
		/// <param name="identifier"></param>
		/// <param name="secret"></param>
		/// <param name="width"></param>
		/// <param name="height"></param>
		/// <param name="issuer"></param>
		/// <returns></returns>
		public static Task<byte[]> GenerateProvisioningImageAsync(string identifier, byte[] secret, int width = 300, int height = 300, string issuer = null)
		{
			var data = Authenticator.UrlEncode($"otpauth://totp/{identifier}?secret={Authenticator.Base32Encode(secret)}&issuer={issuer ?? "VIEApps.net"}");
			return UtilityService.DownloadAsync($"https://chart.apis.google.com/chart?cht=qr&chs={width}x{height}&chl={data}");
		}

		/// <summary>
		/// Generates the url of the QR code bitmap for provisioning
		/// </summary>
		/// <param name="identifier"></param>
		/// <param name="secret"></param>
		/// <param name="width"></param>
		/// <param name="height"></param>
		/// <param name="issuer"></param>
		/// <returns></returns>
		public static async Task<string> GenerateProvisioningImageUrlAsync(string identifier, byte[] secret, int width = 300, int height = 300, string issuer = null)
		{
			var data = await Authenticator.GenerateProvisioningImageAsync(identifier, secret, width, height, issuer).ConfigureAwait(false);
			return UtilityService.GetAppSetting("HttpUri:Files", "https://afs.vieapps.net")
				+ "/otps/" + UtilityService.NewUID.Encrypt(CryptoService.DefaultEncryptionKey, true).Substring(UtilityService.GetRandomNumber(13, 43), 13) + ".png"
				+ "?v=" + CryptoService.Encrypt(data).ToHexa();
		}

		static string UrlEncode(string value)
		{
			var builder = new StringBuilder();
			for (var index = 0; index < value.Length; index++)
			{
				var symbol = value[index];
				if (Authenticator.UrlEncodeAlphabet.IndexOf(symbol) != -1)
					builder.Append(symbol);
				else
				{
					builder.Append('%');
					builder.Append(((int)symbol).ToString("X2"));
				}
			}
			return builder.ToString();
		}

		static string Base32Encode(byte[] data)
		{
			int pos = 0, index = 0;
			var builder = new StringBuilder((data.Length + 7) * Authenticator.InByteSize / Authenticator.OutByteSize);
			while (pos < data.Length)
			{
				var current = data[pos];
				int digit;

				//Is the current digit going to span a byte boundary?
				if (index > (Authenticator.InByteSize - Authenticator.OutByteSize))
				{
					var next = (pos + 1) < data.Length ? data[pos + 1] : 0;
					digit = current & (0xFF >> index);
					index = (index + Authenticator.OutByteSize) % Authenticator.InByteSize;
					digit <<= index;
					digit |= next >> (Authenticator.InByteSize - index);
					pos++;
				}
				else
				{
					digit = (current >> (Authenticator.InByteSize - (index + Authenticator.OutByteSize))) & 0x1F;
					index = (index + Authenticator.OutByteSize) % Authenticator.InByteSize;
					if (index == 0)
						pos++;
				}
				builder.Append(Authenticator.Base32Alphabet[digit]);
			}
			return builder.ToString();
		}
	}
}