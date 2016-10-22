using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace EncryptionDemo
{
    class Program
    {
        // Symmetric Fields
        private const string initVector = "pemgail9uzpgzl88";
        private const int keysize = 256;

        // Asymmetric Fields
        private const string _rsaKeyForEncryption = @"<RSAKeyValue><Modulus>tf5o21jgBKc6dwPMmeZAoa7mZzhMGuXDOW1wV2GX1fyELiOyUjLpRO4ooxG4uF/EfjbC3BpKQnTNVkuooeBKTq2yXF9sHsoeQlAos4EcsrvcsMB2HAj01x4eIv1zieLr85IqwcB9MsgKuJt6wqsdfMeFjxgMge4qL7rLoebcCBc=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        private const string _rsaKeyForDecryption = @"<RSAKeyValue><Modulus>tf5o21jgBKc6dwPMmeZAoa7mZzhMGuXDOW1wV2GX1fyELiOyUjLpRO4ooxG4uF/EfjbC3BpKQnTNVkuooeBKTq2yXF9sHsoeQlAos4EcsrvcsMB2HAj01x4eIv1zieLr85IqwcB9MsgKuJt6wqsdfMeFjxgMge4qL7rLoebcCBc=</Modulus><Exponent>AQAB</Exponent><P>29hC1lehA9a/K++UoFD/AduHJ8e3AjHaMtNIC4kSr21BC+AxzDrguNKdnRkaCdTYmIbHJvZNWW852LUaCVlG/w==</P><Q>0+yTMMYaX1rOSpHnh/htuekl4S9DAnzKjtHWcS4Dw8bYLgveJM64PukpOXwWK9C+V/O4j1e9zyC8Em2to/+W6Q==</Q><DP>Kl05O/606311Z20Kkf4ptdzs5ZCJxqV+q66lQnvOmvmNwFEap4VtCpCjiMNujhhzCKloNSzfaO2TExyLAOQwVw==</DP><DQ>0tMeFr5tTAE9CigeKkE1f2Z2vY9T3Wyh4fTUnWGGc0QkmaJKy1kvJ76yuTI9qDcQtNSL/WXvONg64SZlQKoqyQ==</DQ><InverseQ>tlfR7UYDPIdicc6uHy+w1mQh7FaS++ANLiJFrdi9h9NtK8h0NGoegP7xxq7sxkTFJy7G2DdullfCj17OUXFrIg==</InverseQ><D>A0t8VYBJ6funFNGGSkD/aY3zkOnVguUnACqpjoNvTsn4EKfHyjIuw/c12CHxgLEHKyvNolN9ha98qjPLdUbMwZEVVEnT/Xu3DF0maFuc05cb2DFhxVljdfTzoe+8ubBLmVHgrLJvStkZHMpuR5UF2yzl/9zKqHbSYHqQeYbyB3k=</D></RSAKeyValue>";

        static void Main(string[] args)
        {
            SymmetricEncryptionTest();
            AsymmetricEncryptionTest();
            HybridEncryptionTest();
            HashingTest();            
            Console.ReadLine();
        }

        #region Symmetric Encryption

        private static void SymmetricEncryptionTest()
        {
            // Same public key used for encrypting and decrypting
            // Rijndael, TripleDES

            Console.WriteLine("Starting Symmetric Encryption using Rijndael");

            var textToEncrypt = "Quick Brown Fox";
            Console.WriteLine("Encrypting '{0}'", textToEncrypt);

            var secretKey = "Secret@Key";
            var encryptedText = EncryptString(textToEncrypt, secretKey);

            Console.WriteLine("'{0}' was encrypted to '{1}'", textToEncrypt, encryptedText);

            var decryptedText = DecryptString(encryptedText, secretKey);
            Console.WriteLine("Decrypted text is now '{0}'", decryptedText);
            Console.WriteLine("");
        }

        private static string EncryptString(string plainText, string passPhrase)
        {
            byte[] initVectorBytes = Encoding.UTF8.GetBytes(initVector);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null);
            byte[] keyBytes = password.GetBytes(keysize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();
            byte[] cipherTextBytes = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            return Convert.ToBase64String(cipherTextBytes);
        }

        private static string DecryptString(string cipherText, string passPhrase)
        {
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null);
            byte[] keyBytes = password.GetBytes(keysize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }

        #endregion Symmetric Encryption

        #region Asymmetric Encryption

        private static void AsymmetricEncryptionTest()
        {
            // Use public to encrypt and private to decrypt (referred to as keyset)
            // Private key is superset of public key so you can use private to both encrypt and decrypt
            // You can create keyset in code or using commands: 
            //      aspnet_regiis -pc “MyKeys” -exp
            //      aspnet_regiis -px “MyKeys” c:\temp\mykeys.xml -pri
            // Brutally slow, only use on small size data
            // RSA

            Console.WriteLine("Starting Asymmetric Encryption using RSA");
            
            var textToEncrypt = "Quick Brown Fox";
            Console.WriteLine("Encrypting '{0}'", textToEncrypt);

            var encryptedText = GetCipherText(textToEncrypt);

            Console.WriteLine("'{0}' was encrypted to '{1}'", textToEncrypt, encryptedText);

            var decryptedText = DecryptCipherText(encryptedText);

            Console.WriteLine("Decrypted text is now '{0}'", decryptedText);
            Console.WriteLine("");
        }

        private static RSACryptoServiceProvider CreateCipherForEncryption()
        {
            RSACryptoServiceProvider cipher = new RSACryptoServiceProvider();
            cipher.FromXmlString(_rsaKeyForEncryption);
            return cipher;
        }

        private static RSACryptoServiceProvider CreateCipherForDecryption()
        {
            RSACryptoServiceProvider cipher = new RSACryptoServiceProvider();
            cipher.FromXmlString(_rsaKeyForDecryption);
            return cipher;
        }

        private static void ProgrammaticRsaKeys()
        {
            RSACryptoServiceProvider myRSA = new RSACryptoServiceProvider();
            RSAParameters publicKey = myRSA.ExportParameters(false);
            string xml = myRSA.ToXmlString(true);
        }

        private static string GetCipherText(string plainText)
        {
            RSACryptoServiceProvider cipher = CreateCipherForEncryption();
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = cipher.Encrypt(data, false);
            return Convert.ToBase64String(cipherText);
        }

        private static string DecryptCipherText(string cipherText)
        {
            RSACryptoServiceProvider cipher = CreateCipherForDecryption();
            byte[] original = cipher.Decrypt(Convert.FromBase64String(cipherText), false);
            return Encoding.UTF8.GetString(original);
        }

        #endregion Asymmetric Encryption

        #region Hybrid Encryption

        private static void HybridEncryptionTest()
        {
            // Utilize both Symmetric and Asymmetric Encryption to encypt large text files
            // Encryption:
            //      i.Generate a random key of the length required for symmetrical encryption technique such as AES / Rijndael or similar.
            //      ii.Encrypt your data using AES / Rijndael using that random key generated in part i.
            //      iii.Use RSA encryption to asymmetrically encrypt the random key generated in part i.
            //      Publish(eg write to a file) the outputs from parts ii.and iii.: the AES-encrypted data and the RSA-encrypted random key.
            //  Decryption:
            //      i.Decrypt the AES random key using your private RSA key.
            //      ii. Decrypt the original data using the decrypted AES random key
            //  If we want the benefits of both types of encryption algorithms, the general idea is to create a random symmetric key to encrypt the data, 
            //  then encrypt that key asymmetrically.Once the key is asymmetrically encrypted, we add it to the encrypted message.The receiver gets the key, 
            //  decrypts it with their private key, and uses it to decrypt the message.

          Console.WriteLine("Starting Hybrid Encryption");
            
            Console.WriteLine("");
        }

        #endregion Hybrid Encryption

        #region Hashing

        private static void HashingTest()
        {
            Console.WriteLine("Starting Hashing");

            string password = "myP@5sw0rd";  // original password
            string wrongPassword = "password";    // wrong password

            string passwordHashMD5 =
                   SimpleHash.ComputeHash(password, "MD5", null);
            string passwordHashSha1 =
                   SimpleHash.ComputeHash(password, "SHA1", null);
            string passwordHashSha256 =
                   SimpleHash.ComputeHash(password, "SHA256", null);
            string passwordHashSha384 =
                   SimpleHash.ComputeHash(password, "SHA384", null);
            string passwordHashSha512 =
                   SimpleHash.ComputeHash(password, "SHA512", null);

            Console.WriteLine("COMPUTING HASH VALUES\r\n");
            Console.WriteLine("MD5   : {0}", passwordHashMD5);
            Console.WriteLine("SHA1  : {0}", passwordHashSha1);
            Console.WriteLine("SHA256: {0}", passwordHashSha256);
            Console.WriteLine("SHA384: {0}", passwordHashSha384);
            Console.WriteLine("SHA512: {0}", passwordHashSha512);
            Console.WriteLine("");

            Console.WriteLine("COMPARING PASSWORD HASHES\r\n");
            Console.WriteLine("MD5    (good): {0}",
                                SimpleHash.VerifyHash(
                                password, "MD5",
                                passwordHashMD5).ToString());
            Console.WriteLine("MD5    (bad) : {0}",
                                SimpleHash.VerifyHash(
                                wrongPassword, "MD5",
                                passwordHashMD5).ToString());
            Console.WriteLine("SHA1   (good): {0}",
                                SimpleHash.VerifyHash(
                                password, "SHA1",
                                passwordHashSha1).ToString());
            Console.WriteLine("SHA1   (bad) : {0}",
                                SimpleHash.VerifyHash(
                                wrongPassword, "SHA1",
                                passwordHashSha1).ToString());
            Console.WriteLine("SHA256 (good): {0}",
                                SimpleHash.VerifyHash(
                                password, "SHA256",
                                passwordHashSha256).ToString());
            Console.WriteLine("SHA256 (bad) : {0}",
                                SimpleHash.VerifyHash(
                                wrongPassword, "SHA256",
                                passwordHashSha256).ToString());
            Console.WriteLine("SHA384 (good): {0}",
                                SimpleHash.VerifyHash(
                                password, "SHA384",
                                passwordHashSha384).ToString());
            Console.WriteLine("SHA384 (bad) : {0}",
                                SimpleHash.VerifyHash(
                                wrongPassword, "SHA384",
                                passwordHashSha384).ToString());
            Console.WriteLine("SHA512 (good): {0}",
                                SimpleHash.VerifyHash(
                                password, "SHA512",
                                passwordHashSha512).ToString());
            Console.WriteLine("SHA512 (bad) : {0}",
                                SimpleHash.VerifyHash(
                                wrongPassword, "SHA512",
                                passwordHashSha512).ToString());

            Console.WriteLine("");
        }

        #endregion Hashing
    }
}
