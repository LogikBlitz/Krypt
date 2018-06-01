using System;
using System.Security.Cryptography;
using System.Text;

namespace Krypt.Passwords
{
    public class EncryptionProvider : IEncryptionProvider
    {
        private readonly ICryptography _cryptographyProvider;

        public EncryptionProvider(ICryptography cryptograhyProvider)
        {
            if (cryptograhyProvider == null)
                throw new ArgumentNullException(nameof(cryptograhyProvider),
                    $"{nameof(cryptograhyProvider)} cannot be null");
            _cryptographyProvider = cryptograhyProvider;
        }

        /// <summary>
        ///     Will create a default setup using a <see cref="CryptographySha512" /> hash algorith.
        /// </summary>
        public EncryptionProvider() : this(new CryptographySha512()) {}

        #region Implementation of IPasswordControl

        /// <summary>
        ///     Creates a random Salt with a size that is at least the size specified.
        /// </summary>
        /// <param name="saltMinimumSize">The minimum size of the Salt</param>
        /// <returns>A Salt</returns>
        private string Salt(int saltMinimumSize)
        {
            if (saltMinimumSize <= 0) throw new ArgumentException("saltMinimumSize cannot less or equal to zero");

            // Create a salt with the byte size define by saltSize, using a cryptographically secure random number generator
            var saltData = new byte[saltMinimumSize];
            var cryptoProviderService = new RNGCryptoServiceProvider();
            cryptoProviderService.GetNonZeroBytes(saltData);

            //Returns the salt data as a string representation
            return Convert.ToBase64String(saltData);
        }


        /// <summary>
        ///     Hashes a originalData by prepending the Salt then hashing the whole string.
        /// </summary>
        /// <param name="originalData">The password string to hash</param>
        /// <param name="salt">The salt to use</param>
        /// <returns>A hashed combination of salt and password</returns>
        public string Encrypt(string originalData, string salt)
        {
            // Convert the string original value to a byte array
            var dataAsBytes = Encoding.UTF8.GetBytes(originalData);

            var saltDataAsBytes = Encoding.UTF8.GetBytes(salt);

            // prepend the salt to the beginning of the original
            var saltedPasswordData = new byte[originalData.Length + salt.Length];

            Array.Copy(saltDataAsBytes, 0, saltedPasswordData, 0, salt.Length);
            Array.Copy(dataAsBytes, 0, saltedPasswordData, salt.Length, originalData.Length);

            var hashed = _cryptographyProvider.ComputeHash(Convert.ToBase64String(saltedPasswordData));

            return hashed;
        }

        /// <summary>
        ///     Validates the hashedPassword against the provided password and hash.
        /// </summary>
        /// <param name="original">The password to validate</param>
        /// <param name="salt">The salt used to created the hashedPassword</param>
        /// <param name="encrypted">The original hashed password</param>
        /// <returns>true if password corresponds to the hashed, else false</returns>
        public bool Validate(string original, string salt, string encrypted)
        {
            var generatedHash = Encrypt(original, salt);
            return (generatedHash.Equals(encrypted));
        }

        /// <summary>
        ///     Creates a Cryptological secure password randomly.
        /// </summary>
        /// <param name="minimumLength">The minimum lenght of the password</param>
        /// <returns>a password</returns>
        public string RandomPassword(int minimumLength)
        {
            if (minimumLength <= 0)
                throw new ArgumentException("minimumLength of a random password must be larger than zero.",
                    nameof(minimumLength));
            return Salt(minimumLength);
        }

        /// <summary>
        ///     Creates a Cryptological secure password randomly using the defaul;t length defined by the
        ///     <see cref="ICryptography.MinimumSaltLength" />
        /// </summary>
        /// <returns>a password</returns>
        public string RandomPassword()
        {
            return RandomPassword(_cryptographyProvider.MinimumSaltLength);
        }


        /// <summary>
        ///     Generates a random Salt with the length defined in <see cref="ICryptography.MinimumSaltLength" />c
        /// </summary>
        /// <returns>A cryptografic random Salt</returns>
        public string GenerateSalt()
        {
            return RandomPassword();
        }

        #endregion
    }
}