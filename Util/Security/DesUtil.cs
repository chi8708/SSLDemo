using System;
using System.Security.Cryptography;
using System.Text;

namespace Util.Security
{
    internal class DesUtil
    {
        private static readonly CipherMode Mode = CipherMode.CBC;
        private static readonly PaddingMode Padding = PaddingMode.PKCS7;

        /// <summary>
        /// DES ����
        /// </summary>
        /// <param name="sSource">Դ�ַ���</param>
        /// <param name="key">��Կ</param>
        /// <returns>���ܺ���ַ���</returns>
        public static string DesEncryptString(string sSource, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] iv = new byte[8];
            byte[] sourceBytes = Encoding.UTF8.GetBytes(sSource);

            using (var des = DES.Create())
            {
                des.Key = keyBytes;
                des.IV = iv;
                des.Mode = Mode;
                des.Padding = Padding;

                using (var encryptor = des.CreateEncryptor())
                {
                    byte[] cipherBytes = encryptor.TransformFinalBlock(sourceBytes, 0, sourceBytes.Length);
                    return Convert.ToBase64String(cipherBytes);
                }
            }
        }

        /// <summary>
        /// DES ����
        /// </summary>
        /// <param name="sSource">���ܺ���ַ���</param>
        /// <param name="key">��Կ</param>
        /// <returns>���ܺ���ַ���</returns>
        public static string DesDecryptString(string sSource, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] iv = new byte[8];
            byte[] sourceBytes = Convert.FromBase64String(sSource);

            
            using (var des = DES.Create())
            {
                des.Key = keyBytes;
                des.IV = iv;
                des.Mode = Mode;
                des.Padding = Padding;

                using (var decryptor = des.CreateDecryptor())
                {
                    byte[] plainBytes = decryptor.TransformFinalBlock(sourceBytes, 0, sourceBytes.Length);
                    return Encoding.UTF8.GetString(plainBytes);
                }
            }



        }
    }
}
