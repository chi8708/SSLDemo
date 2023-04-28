using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace GemmyActive
{
    class PKCS7Tool
    {
        public static byte[] DecodeFromFile(string inFileName)
        {
            FromBase64Transform myTransform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);

            byte[] myOutputBytes = new byte[myTransform.OutputBlockSize];

            //Open the input and output files.
            FileStream myInputFile = new FileStream(inFileName, FileMode.Open, FileAccess.Read);

            //Retrieve the file contents into a byte array.
            byte[] myInputBytes = new byte[myInputFile.Length];
            myInputFile.Read(myInputBytes, 0, myInputBytes.Length);

            MemoryStream outputDataStream = new MemoryStream(myInputBytes.Length);

            //Transform the data in chunks the size of InputBlockSize.
            int i = 0;
            int inputBlockSize = 4;
            while (myInputBytes.Length - i > inputBlockSize)
            {
                int nOutput = myTransform.TransformBlock(myInputBytes, i, inputBlockSize, myOutputBytes, 0);
                i += inputBlockSize;
                if (nOutput > 0)
                {
                    outputDataStream.Write(myOutputBytes, 0, nOutput);
                }
            }

            //Transform the final block of data.
            myOutputBytes = myTransform.TransformFinalBlock(myInputBytes, i, myInputBytes.Length - i);
            outputDataStream.Write(myOutputBytes, 0, myOutputBytes.Length);

            //Free up any used resources.
            myTransform.Clear();

            myInputFile.Close();
            outputDataStream.Position = 0;
            byte[] outputData = new byte[outputDataStream.Length];
            outputDataStream.Read(outputData, 0, (int)outputDataStream.Length);
            outputDataStream.Close();

            return outputData;
        }

        public static Boolean Verify(byte[] sig, byte[] msg,string dn)
        {
            Boolean b = true;
            try
            {
                ContentInfo signedData = new ContentInfo(msg);
                SignedCms cms = new SignedCms(signedData, true);
                cms.Decode(sig);
                //Check Signature
                cms.CheckSignature(true);
                //Check dn
                if (cms.Certificates.Count > 0 )
                {
                    X509Certificate2 cert = cms.Certificates[0];
                    if (!string.IsNullOrEmpty(dn) && !dn.Equals(cert.Subject))
                    {
                        b = false;
                    }
                }

                byte[] data = cms.Encode();
            }
            catch (Exception e)
            {
                b = false;
            }
            return b;
        }

        //PKCS #7签名 算法
        public enum SignOid 
        {
            SHA1,
            SHA256
        }

        private class SignOidUtil 
        {
            private static Dictionary<SignOid, Oid> oids = new Dictionary<SignOid, Oid>()
            {
              {SignOid.SHA1, new Oid("1.3.14.3.2.26", "SHA1")},
              {SignOid.SHA256, new Oid("2.16.840.1.101.3.4.2.1", "SHA256")}
            };

            public static Oid GetSignOid(SignOid type)
            {
               return oids[type];
            }
        }

        /// <summary>
        /// PKCS #7签名
        /// </summary>
        /// <param name="certFileName"></param>
        /// <param name="password"></param>
        /// <param name="dataTobeSign"></param>
        /// <param name="outputFileName"></param>
        /// <returns></returns>
        public static string SignatureMessage(string certFileName, string password, byte[] dataTobeSign, string outputFileName="", SignOid signOid=SignOid.SHA256)
        {
            byte[] pfxCert = File.ReadAllBytes(certFileName);
          //  byte[] dataTobeSign = File.ReadAllBytes(dataFileName);
            SecureString pwd = new SecureString();
            char[] pwdCharArray = password.ToCharArray();
            for (int i = 0; i < pwdCharArray.Length; i++)
            {
                pwd.AppendChar(pwdCharArray[i]);
            }
            X509Certificate2 cert = new X509Certificate2(pfxCert, pwd);
            CmsSigner signer = new CmsSigner(cert);
            signer.DigestAlgorithm = SignOidUtil.GetSignOid(signOid);
            signer.IncludeOption = X509IncludeOption.EndCertOnly;

            ContentInfo signedData = new ContentInfo(dataTobeSign);
            SignedCms cms = new SignedCms(signedData,true);

            cms.ComputeSignature(signer,true);
            byte[] signature = cms.Encode();
            return Convert.ToBase64String(signature);
        }

        public static byte[] DecodeFromString(string signString)
        {
            FromBase64Transform myTransform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces);

            byte[] myOutputBytes = new byte[myTransform.OutputBlockSize];

            //Open the input and output files.

            //Retrieve the file contents into a byte array.
            byte[] myInputBytes = System.Text.Encoding.UTF8.GetBytes(signString);

            MemoryStream outputDataStream = new MemoryStream(myInputBytes.Length);

            //Transform the data in chunks the size of InputBlockSize.
            int i = 0;
            int inputBlockSize = 4;
            while (myInputBytes.Length - i > inputBlockSize)
            {
                int nOutput = myTransform.TransformBlock(myInputBytes, i, inputBlockSize, myOutputBytes, 0);
                i += inputBlockSize;
                if (nOutput > 0)
                {
                    outputDataStream.Write(myOutputBytes, 0, nOutput);
                }
            }

            //Transform the final block of data.
            myOutputBytes = myTransform.TransformFinalBlock(myInputBytes, i, myInputBytes.Length - i);
            outputDataStream.Write(myOutputBytes, 0, myOutputBytes.Length);

            //Free up any used resources.
            myTransform.Clear();
            outputDataStream.Position = 0;
            byte[] outputData = new byte[outputDataStream.Length];
            outputDataStream.Read(outputData, 0, (int)outputDataStream.Length);
            outputDataStream.Close();

            return outputData;
        }
    }
}
