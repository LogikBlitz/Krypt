using System;
using System.Security.Cryptography;
using System.Text;

namespace Krypt.Passwords
{
    /// <summary>
    ///     Creates cryptograhical safe hashes using the
    ///     <see cref="System.Security.Cryptography.SHA512Managed" />
    ///     hashing algorithm
    /// </summary>
    public class CryptographySha512 : ICryptography
    {
        /// <summary>
        ///     Computes a secure hash from the input data.
        /// </summary>
        /// <param name="data">The data to hash</param>
        /// <returns>The hashvalue created from the <see cref="data" /></returns>
        public string ComputeHash(string data)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException($"{nameof(data)} cannot be null or empty string", nameof(data));
            var hashAlgorithm = new SHA512Managed();
            var dataAsBytes = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(hashAlgorithm.ComputeHash(dataAsBytes));
        }

        /// <summary>
        ///     Provides info on the complexity of the algorithms output fron <see cref="ICryptography.ComputeHash" />.
        ///     Basically it provides a hint on as to how long the output is in regards
        ///     to creating minimum salting that relate to the hashing
        /// </summary>
        public int MinimumSaltLength => 64;
    }
}