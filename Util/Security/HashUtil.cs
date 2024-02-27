using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Util.Security
{
    internal class HashUtil
    {
        //SHA1哈希加密算法  
        public static string SHA1_Hash(string str_sha1_in)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            byte[] bytes_sha1_in = System.Text.UTF8Encoding.Default.GetBytes(str_sha1_in);
            byte[] bytes_sha1_out = sha1.ComputeHash(bytes_sha1_in);
            string str_sha1_out = BitConverter.ToString(bytes_sha1_out);
            str_sha1_out = str_sha1_out.Replace("-", "").ToLower();
            return str_sha1_out;
        }

        //SHA256哈希加密算法
        public static string SHA256_Hash(string str_sha256_in)
        {
            SHA256 sha256 = new SHA256CryptoServiceProvider();
            byte[] bytes_sha256_in = System.Text.UTF8Encoding.Default.GetBytes(str_sha256_in);
            byte[] bytes_sha256_out = sha256.ComputeHash(bytes_sha256_in);
            string str_sha256_out = BitConverter.ToString(bytes_sha256_out);
            str_sha256_out = str_sha256_out.Replace("-", "").ToLower();
            return str_sha256_out;
        }

        //SHA384哈希加密算法

        public static string SHA384_Hash(string str_sha384_in)
        {
            SHA384 sha384 = new SHA384CryptoServiceProvider();
            byte[] bytes_sha384_in = System.Text.UTF8Encoding.Default.GetBytes(str_sha384_in);
            byte[] bytes_sha384_out = sha384.ComputeHash(bytes_sha384_in);
            string str_sha384_out = BitConverter.ToString(bytes_sha384_out);
            str_sha384_out = str_sha384_out.Replace("-", "").ToLower();
            return str_sha384_out;
        }

        //SHA512哈希加密算法

        public static string SHA512_Hash(string str_sha512_in)
        {
            SHA512 sha512 = new SHA512CryptoServiceProvider();
            byte[] bytes_sha512_in = System.Text.UTF8Encoding.Default.GetBytes(str_sha512_in);
            byte[] bytes_sha512_out = sha512.ComputeHash(bytes_sha512_in);
            string str_sha512_out = BitConverter.ToString(bytes_sha512_out);
            str_sha512_out = str_sha512_out.Replace("-", "").ToLower();
            return str_sha512_out;
        }
    }
}
