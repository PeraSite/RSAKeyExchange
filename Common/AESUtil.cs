using System;
using System.IO;
using System.Security.Cryptography;

namespace Common {
	public static class AESUtil {
		public static byte[] Encrypt(string plainText, Aes aes) => Encrypt(plainText, aes.Key, aes.IV);

		public static byte[] Encrypt(string plainText, byte[] key, byte[] iv) {
			if (plainText is not {Length: > 0})
				throw new ArgumentNullException(nameof(plainText));
			if (key is not {Length: > 0})
				throw new ArgumentNullException(nameof(key));
			if (iv is not {Length: > 0})
				throw new ArgumentNullException(nameof(iv));

			using Aes aes = Aes.Create();
			aes.Key = key;
			aes.IV = iv;

			ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

			using MemoryStream msEncrypt = new MemoryStream();
			using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
			using (StreamWriter swEncrypt = new StreamWriter(csEncrypt)) {
				swEncrypt.Write(plainText);
			}

			var encrypted = msEncrypt.ToArray();
			return encrypted;
		}

		public static string Decrypt(byte[] cipherText, Aes aes) => Decrypt(cipherText, aes.Key, aes.IV);

		public static string Decrypt(byte[] cipherText, byte[] key, byte[] iv) {
			if (cipherText is not {Length: > 0})
				throw new ArgumentNullException(nameof(cipherText));
			if (key is not {Length: > 0})
				throw new ArgumentNullException(nameof(key));
			if (iv is not {Length: > 0})
				throw new ArgumentNullException(nameof(iv));

			using Aes aesAlg = Aes.Create();
			aesAlg.Key = key;
			aesAlg.IV = iv;

			ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

			using MemoryStream msDecrypt = new MemoryStream(cipherText);
			using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
			using StreamReader srDecrypt = new StreamReader(csDecrypt);
			var plaintext = srDecrypt.ReadToEnd();

			return plaintext;
		}
	}
}
