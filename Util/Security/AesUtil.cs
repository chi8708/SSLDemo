using System;
using System.Security.Cryptography;
using System.Text;

namespace Util.Security
{
    internal class AesUtil
    {
        // AES加密
        public static string Encrypt(string plainText, string key, string iv)
        {
            byte[] encryptedBytes;
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = Encoding.UTF8.GetBytes(iv);

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new System.IO.MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return Convert.ToBase64String(encryptedBytes);
        }

        // AES解密
        public static string Decrypt(string encryptedText, string key, string iv)
        {
            byte[] decryptedBytes;
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = Encoding.UTF8.GetBytes(iv);

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new System.IO.MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                        cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        // 生成AES密钥
            
        public static string CreateSecretKey()
        {
            string uuid = Guid.NewGuid().ToString().Replace("-", "");
            StringBuilder sb = new StringBuilder();
            sb.Append(uuid);
            while (sb.Length < 16)
            {
                sb.Append("0");
            }
            if (sb.Length > 16)
            {
                sb = new StringBuilder(sb.ToString().Substring(0, 16));
            }
            return sb.ToString();
        }
    }
}
