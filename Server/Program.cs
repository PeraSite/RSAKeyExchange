using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Common;

namespace Server {
	internal static class Program {
		private static void Main() {
			// TCP 서버 시작
			var server = new TcpListener(IPAddress.Any, Setting.PORT);
			server.Start();

			while (true) {
				// TCP Client Accept
				var client = server.AcceptTcpClient();

				Console.WriteLine(client.Client.RemoteEndPoint);

				// Stream 만들기
				var stream = client.GetStream();
				var br = new BinaryReader(stream);
				var bw = new BinaryWriter(stream);

				//////////////////////////
				// RSA Key exchange 시작 //
				//////////////////////////

				// 1. 클라이언트가 전송해온 RSA 공개 키 읽기
				var publicKeyLength = br.ReadInt32();
				var publicKey = br.ReadBytes(publicKeyLength);

				// 2. 읽어온 공개 키로 RSA 객체 만들기
				using var rsa = new RSACryptoServiceProvider();
				rsa.ImportRSAPublicKey(publicKey, out _);

				// 3. 클라이언트와 암호화해 공유할 AES 객체 만들기
				using var aes = Aes.Create();
				var aesKey = aes.Key;
				var aesIV = aes.IV;

				// 4. AES key, iv 암호화
				var encryptedAesKey = rsa.Encrypt(aesKey, Setting.OAEP);
				var encryptedAesIV = rsa.Encrypt(aesIV, Setting.OAEP);

				// 5. key, iv 전송
				bw.Write(encryptedAesKey.Length);
				bw.Write(encryptedAesKey);
				bw.Write(encryptedAesIV.Length);
				bw.Write(encryptedAesIV);

				// 6. 이후 같은 AES 키로 복호화해 메시지 읽기
				while (stream.CanRead) {
					var encryptedTextLength = br.ReadInt32();
					var encryptedText = br.ReadBytes(encryptedTextLength);

					var text = AESUtil.Decrypt(encryptedText, aes);
					Console.WriteLine(text);
				}
			}
		}
	}
}
