using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace System.Text.Cryptography
{
   
    public static class StringCryptography
    {

        /// <summary>
        /// Generates a 32 byte encryption key.
        /// </summary>
        /// <returns>encryption key opf 32 bytes</returns>
        public static string GenerateCipherKey()
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.GenerateKey();
                var key = aesAlg.Key;
                return Convert.ToBase64String(key);
            }
        }
        
        
        /// <summary>
        /// Extension method. Encrypt a string using the provided string key with the AES algorithm
        /// </summary>
        /// <param name="toEncrypt">the string to encrypt</param>
        /// <param name="key">the key to use for encryption.Key must be 32 bytes </param>
        /// <returns>cipher text</returns>
        public static string Encrypt(this string toEncrypt, string key)
        {
            return EncryptString(toEncrypt, key);
        }
        
        /// <summary>
        /// Encrypt a string using the provided string key using the AES algorithm
        /// </summary>
        /// <param name="toEncrypt">the string to encrypt</param>
        /// <param name="keyString">the key to use for encryption. Key must be 32 bytes</param>
        /// <returns>cipher text</returns>
        public static string EncryptString(string toEncrypt, string keyString)
        {
            if (string.IsNullOrWhiteSpace(toEncrypt)) throw new ArgumentException("cannot be null, empty or whitespace",nameof(toEncrypt));
            if (string.IsNullOrWhiteSpace(keyString)) throw new ArgumentException("cannot be null, empty or whitespace",nameof(keyString));

            var key =  Convert.FromBase64String(keyString);

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(toEncrypt);
                        }

                        var iv = aesAlg.IV;

                        var decryptedContent = msEncrypt.ToArray();

                        var result = new byte[iv.Length + decryptedContent.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }


        /// <summary>
        /// Extension method: Decrypt a AES cipher string using the provided key
        /// </summary>
        /// <param name="cipherText">The cipher text to decrypt</param>
        /// <param name="key">The key used to decrypt. Key must be 32 bytes</param>
        /// <returns>The decrypted cipher</returns>
        public static string Dencrypt(this string cipherText, string key)
        {
            return DecryptString(cipherText, key);
        }

        /// <summary>
        /// Decrypt a AES cipher string using the provided key
        /// </summary>
        /// <param name="cipherText">The cipher text to decrypt</param>
        /// <param name="cipherKey">The key used to decrypt. Key must be 32 bytes</param>
        /// <returns>The decrypted cipher</returns>
        public static string DecryptString(string cipherText, string cipherKey)
        {
            if (string.IsNullOrWhiteSpace(cipherText)) throw new ArgumentException("cannot be null, empty or whitespace",nameof(cipherText));
            if (string.IsNullOrWhiteSpace(cipherKey)) throw new ArgumentException("cannot be null, empty or whitespace",nameof(cipherKey));
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, fullCipher.Length - iv.Length);
            var key = Convert.FromBase64String(cipherKey);

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }
    }
}