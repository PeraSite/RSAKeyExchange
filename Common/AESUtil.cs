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

			// AES 객체 생성
			using Aes aes = Aes.Create();
			aes.Key = key;
			aes.IV = iv;

			// Encryptor 생성 
			ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

			// MemoryStream에 plain text 쓰기
			using MemoryStream ms = new MemoryStream();
			using CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
			using (StreamWriter sw = new StreamWriter(cs)) {
				sw.Write(plainText);
			}

			// MemoryStream에 쓰인 바이트 배열로 변환해 반환
			var encrypted = ms.ToArray();
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

			// AES 객체 생성
			using Aes aes = Aes.Create();
			aes.Key = key;
			aes.IV = iv;

			// Decryptor 생성
			ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

			// cipher text를 담은 MemoryStream 만들기
			using MemoryStream ms = new MemoryStream(cipherText);
			using CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
			using StreamReader sr = new StreamReader(cs);

			// MemoryStream을 래핑한 StreamReader로 복호화된 문자열 읽기
			var plaintext = sr.ReadToEnd();
			return plaintext;
		}
	}
}
