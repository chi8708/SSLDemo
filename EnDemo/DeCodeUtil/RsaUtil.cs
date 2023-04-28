using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EnDemo
{
    //可用 cbcActive在用
    public class RsaUtil
    {
        /// <summary>
        /// generate private key and public key arr[0] for private key arr[1] for public key
        /// </summary>
        /// <returns></returns>
        public static string[] GenerateKeys()
        {
            string[] sKeys = new String[2];
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            sKeys[0] = rsa.ToXmlString(true);
            sKeys[1] = rsa.ToXmlString(false);
            return sKeys;
        }

        /// <summary>
        /// RSA Encrypt
        /// </summary>
        /// <param name="sSource" >Source string</param>
        /// <param name="sPublicKey" >public key</param>
        /// <returns></returns>
        public static string EncryptString(string sSource, string sPublicKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
           
            string plaintext = sSource;
            rsa.FromXmlString(sPublicKey);
            byte[] cipherbytes;
            cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), false);

            return Convert.ToBase64String(cipherbytes);
        }

        /// <summary>
        /// RSA Decrypt
        /// </summary>
        /// <param name="sSource">Source string</param>
        /// <param name="sPrivateKey">Private Key</param>
        /// <returns></returns>
        public static string DecryptString(string sSource, string sPrivateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(sPrivateKey);
            
            byte[] plaintbytes = rsa.Decrypt(Convert.FromBase64String(sSource), false);
            return Encoding.UTF8.GetString(plaintbytes);
        }

        /// <summary>
        /// RSA Decrypt
        /// </summary>
        /// <param name="sSource">Source string</param>
        /// <param name="sPrivateKey">Private Key</param>
        /// <returns></returns>
        public static string DecryptStringNoXml(string sSource, string sPrivateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(sPrivateKey);

            byte[] plaintbytes = rsa.Decrypt(Convert.FromBase64String(sSource), false);
            return Encoding.UTF8.GetString(plaintbytes);
        }





        //RSACryptoServiceProvider pubkey = (RSACryptoServiceProvider)pubCert.PublicKey.Key;
        ////byte[] encryptedData = pubkey.Encrypt(Encoding.UTF8.GetBytes(key), true);
        //var encryptedData = RsaUtil.RSAEncrypt(Encoding.UTF8.GetBytes(key), pubkey.ExportParameters(false), false);
        //var skey2 = Convert.ToBase64String(encryptedData);
        [Obsolete]
        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding=false)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {

                return null;
            }


        }

        [Obsolete]
        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding=false)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                return null;
            }

        }



        /// <summary>
        /// PKCS8 私钥文本 转 .NET XML 私钥文本
        /// </summary>
        /// <param name="privateKeyPemPkcs8"></param>
        /// <returns></returns>
        public static string RSAPrivateKeyJava2DotNet(string privateKeyPemPkcs8)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyPemPkcs8));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
            Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }


        /// <summary>
        /// PKCS8 文本转XML对象
        /// </summary>
        /// <param name="privateKeyPemPkcs8"></param>
        /// <returns></returns>
        public static string LoadPrivateKeyPKCS8(string privateKeyPemPkcs8)
        {

            try
            {
                //PKCS8是“BEGIN PRIVATE KEY”
                privateKeyPemPkcs8 = privateKeyPemPkcs8.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\r", "").Replace("\n", "").Trim();
                privateKeyPemPkcs8 = privateKeyPemPkcs8.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r", "").Replace("\n", "").Trim();

                //pkcs8 文本先转为 .NET XML 私钥字符串
                string privateKeyXml = RSAPrivateKeyJava2DotNet(privateKeyPemPkcs8);

                return privateKeyXml;

                //RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
                //publicRsa.FromXmlString(privateKeyXml);
                //return publicRsa;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }


    }
}
