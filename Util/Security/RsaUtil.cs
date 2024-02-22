using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Util.Security
{
    internal class RsaUtil
    {
        /// <summary>
        /// RSA 加密
        /// </summary>
        /// <param name="sSource" >Source string</param>
        /// <param name="sPublicKey" >public key</param>
        /// <returns></returns>
        public static string RsaEncryptString(string sSource, string publicKeyString)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyString);
            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKeyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            var cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(sSource), false);
            return Convert.ToBase64String(cipherbytes);
        }
    }
}
