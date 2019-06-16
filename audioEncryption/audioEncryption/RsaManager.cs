using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AudioEncryption
{
    static class RsaManager
    {
        static private BigInteger p1;
        static private BigInteger p2;
        static private BigInteger n;
        static private BigInteger phin;
        static private BigInteger e;
        static private BigInteger d;
        static public int EncryptedDataLength { get; private set; } = 0;

        /// <summary>
        /// Encrypts given data and returns it, gives null without key
        /// </summary>
        /// <param name="data">Data array to be encrypted</param>
        /// <returns>Encrypted data, null if key is null</returns>
        public static byte[] Encrypt(byte[] data)
        {
            if (e == 0 || n == 0)
                return null;
            var result = BigInteger.ModPow(new BigInteger(data), e, n).ToByteArray();
            return result;
        }

        /// <summary>
        /// Decrypts data and returns it, gives null without key
        /// </summary>
        /// <param name="encryptedData">Encrypted data array to be decrypted</param>
        /// <returns>Decrypted data, null if key is null</returns>
        public static byte[] Decrypt(byte[] encryptedData)
        {
            if (d == 0 || n == 0)
                return null;
            var result = BigInteger.ModPow(new BigInteger(encryptedData), d, n).ToByteArray();
            return result;
        }

        /// <summary>
        /// Generate pair of public and private keys
        /// </summary>
        public static void GenerateKeyPar()
        {
            int byteLength = 32;
            p1 = GenerateRandomPrime(byteLength);
            p2 = GenerateRandomPrime(byteLength);

            while (p2 == p1)
                p2 = GenerateRandomPrime(byteLength);
            phin = (p1 - 1) * (p2 - 1);

            while (BigInteger.GreatestCommonDivisor(phin, e) != 1)
            {

                e = RandomNumberGenerator(10, 99);
            }
            n = p1 * p2;
            d = MultiplicativeInverse(e, phin);
            EncryptedDataLength = n.ToByteArray().Length;
        }

        /// <summary>
        /// Returns key serialized to string
        /// </summary>
        /// <param name="privateOrPublic">true - return private key, false - return public key</param>
        /// <returns>returns specified key as serialized string</returns>
        public static string GetKeyString(bool privateOrPublic)
        {
            string key;

            if (privateOrPublic)
                key = d + "," + n + "," + EncryptedDataLength;
            else
                key = e + "," + n + "," + EncryptedDataLength;

            return key;
        }

        /// <summary>
        /// Sets key to the serialized string
        /// </summary>
        /// <param name="privateOrPublic">true - return private key, false - return public key</param>
        /// <param name="keyString">key serialized as string</param>
        public static void SetKey(bool privateOrPublic, string keyString)
        {
            string[] parameterList = keyString.Split(',');
            if (parameterList.Count() == 3)
            {
                if (privateOrPublic)
                    d = BigInteger.Parse(parameterList[0]);
                else
                    e = BigInteger.Parse(parameterList[0]);

                n = BigInteger.Parse(parameterList[1]);
                EncryptedDataLength = Int32.Parse(parameterList[2]);
            }
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

        /// <summary>
        /// Generates random number between set parameters
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <returns></returns>
        public static BigInteger RandomNumberGenerator(BigInteger min, BigInteger max)
        {
            Random random = new Random();
            byte[] buffor = new byte[8];
            random.NextBytes(buffor);
            BigInteger result = BigInteger.Abs(new BigInteger(buffor));
            result = (result % (max - min)) + min;
            return result;
        }

        /// <summary>
        /// Generates random number that takes set number of bytes
        /// </summary>
        /// <param name="byteNumber">Number length in bytes</param>
        /// <returns></returns>
        public static BigInteger RandomNumberGenerator(int byteNumber)
        {
            Random random = new Random();
            byte[] buffor = new byte[byteNumber];
            random.NextBytes(buffor);
            BigInteger result = BigInteger.Abs(new BigInteger(buffor));
            return result;
        }

        /// <summary>
        /// Tests if number is a prime number
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        public static bool MillerRabinTest(BigInteger n)
        {
            BigInteger r, a, b;
            int s = 0;
            for (r = n - 1; r % 2 == 0; s++)
                r /= 2;
            if (r == n - 1) return false;
            bool isPrime = false;
            for (int i = 0; i < 100; i++)
            {
                a = RandomNumberGenerator(1, n - 1);
                b = BigInteger.ModPow(a, r, n);
                if (b == 1 || b == n - 1)
                {
                    isPrime = true;
                }
                else
                {
                    for (uint j = 1; j < s; j++)
                    {
                        b = BigInteger.ModPow(a, 2 * j * r, n);
                        if (b == n - 1)
                            isPrime = true; break;
                    }
                }
                if (!isPrime)
                    return false;
                else
                    isPrime = false;
            }
            return true;
        }

        /// <summary>
        /// Generates random prime number that takes set amount of bytes
        /// </summary>
        /// <param name="byteNumber">Number length in bytes</param>
        /// <returns></returns>
        public static BigInteger GenerateRandomPrime(int byteNumber)
        {
            BigInteger possiblePrime = RandomNumberGenerator(byteNumber);
            while (!MillerRabinTest(possiblePrime))
                possiblePrime = RandomNumberGenerator(byteNumber);
            return possiblePrime;
        }

        /// <summary>
        /// Returns multiplicative inverse
        /// </summary>
        /// <param name="e"></param>
        /// <param name="fi"></param>
        /// <returns></returns>
        public static BigInteger MultiplicativeInverse(BigInteger e, BigInteger fi)
        {
            BigInteger result;
            int k = 1;
            while (true)
            {
                var part = (1 + (k * fi));
                if (BigInteger.Remainder(part, e) == 0)
                {
                    result = part / e;
                    if ((result % 1) == 0)
                    {
                        return result;
                    }
                }
                k++;
            }
        }
    }
}
