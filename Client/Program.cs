using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Common;

namespace Client {
	internal static class Program {
		private static void Main() {
			// TCP 연결
			var client = new TcpClient();
			client.Connect(IPAddress.Loopback, Setting.PORT);

			// Stream 만들기
			var stream = client.GetStream();
			var br = new BinaryReader(stream);
			var bw = new BinaryWriter(stream);

			// RSA Key-pair 만들기
			using var rsa = new RSACryptoServiceProvider();
			var publicKey = rsa.ExportRSAPublicKey();

			//////////////////////////
			// RSA Key exchange 시작 //
			//////////////////////////

			// 1. 클라이언트 공개 키 전송
			bw.Write(publicKey.Length);
			bw.Write(publicKey);

			// 2. 클라이언트 개인 키로 암호화 된 서버 AES 키 읽기
			var encryptedAesKeyLength = br.ReadInt32();
			var encryptedAesKey = br.ReadBytes(encryptedAesKeyLength);

			var encryptedAesIVLength = br.ReadInt32();
			var encryptedAesIV = br.ReadBytes(encryptedAesIVLength);

			// 3. 클라이언트 개인 키로 암호화된 서버 키 복호화
			var decryptedAesKey = rsa.Decrypt(encryptedAesKey, Setting.OAEP);
			var decryptedAesIV = rsa.Decrypt(encryptedAesIV, Setting.OAEP);

			// 4. 복호화된 서버 키로 AES 객체 만들기
			using var aes = Aes.Create();
			aes.Key = decryptedAesKey;
			aes.IV = decryptedAesIV;

			// 5. 이후 같은 AES 키로 암호화해 메시지 전송
			while (true) {
				var text = Console.ReadLine();
				if (string.IsNullOrEmpty(text)) break;

				var encryptedText = AESUtil.Encrypt(text, aes);

				bw.Write(encryptedText.Length);
				bw.Write(encryptedText);
				bw.Flush();
			}
		}
	}
}
