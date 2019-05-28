using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AudioEncryption
{
    static class RsaManager
    {
        static private RSAParameters publicKey;
        static private RSAParameters privateKey;
        static private int keySize = 2048;

        /// <summary>
        /// Encrypts given data and returns it, gives null without key
        /// </summary>
        /// <param name="data"></param>
        /// <returns>Encrypted data, null if key is null</returns>
        public static byte[] Encrypt(byte[] data)
        {
            if (publicKey.Modulus == null)
                return null;
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey);
                return rsa.Encrypt(data, true);
            }
        }

        /// <summary>
        /// Decrypts data and returns it, gives null without key
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <returns>Decrypted data, null if key is null</returns>
        public static byte[] Decrypt(byte[] encryptedData)
        {
            if (privateKey.P == null)
                return null;
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                return rsa.Decrypt(encryptedData, true);
            }
        }

        /// <summary>
        /// Generate pair of public and private keys
        /// </summary>
        public static void generateKeyPar()
        {
            using (var rsa = new RSACryptoServiceProvider(keySize))
            {
                rsa.PersistKeyInCsp = false;
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
            }
        }

        /// <summary>
        /// Returns key serialized to string
        /// </summary>
        /// <param name="privateOrPublic">true - return private key, false - return public key</param>
        /// <returns>returns specified key as serialized string</returns>
        public static string GetKeyString(bool privateOrPublic)
        {
            RSAParameters key;

            if (privateOrPublic)
                key = privateKey;
            else
                key = publicKey;

            var sw = new System.IO.StringWriter();
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, key);

            return sw.ToString();
        }

        /// <summary>
        /// Sets key to the serialized string
        /// </summary>
        /// <param name="privateOrPublic">true - return private key, false - return public key</param>
        /// <param name="keyString">key serialized as string</param>
        public static void SetKey(bool privateOrPublic, string keyString)
        {
            var sr = new System.IO.StringReader(keyString);
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));

            if (privateOrPublic)
                privateKey = (RSAParameters)xs.Deserialize(sr);
            else
                publicKey = (RSAParameters)xs.Deserialize(sr);
        }

        /// <summary>
        /// Writes specified key to file
        /// </summary>
        /// <param name="privateOrPublic">true - return private key, false - return public key</param>
        /// <param name="FileName"></param>
        public static void WriteKeysToFile(bool privateOrPublic, string FileName)
        {
            using (StreamWriter outputFile = new StreamWriter(FileName, false, Encoding.UTF8))
            {
                outputFile.Write(GetKeyString(privateOrPublic));
            }
        }

        /// <summary>
        /// Writes both keys to separate files
        /// </summary>
        /// <param name="privateKeyFileName"></param>
        /// <param name="publicKeyFileName"></param>
        public static void WriteKeysToFile(string privateKeyFileName, string publicKeyFileName)
        {
            WriteKeysToFile(true, privateKeyFileName);
            WriteKeysToFile(false, publicKeyFileName);
        }
    }
}
