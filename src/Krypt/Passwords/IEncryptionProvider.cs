namespace Krypt.Passwords
{
    public interface IEncryptionProvider {
        /// <summary>
        ///     Hashes a originalData by prepending the Salt then hashing the whole string.
        /// </summary>
        /// <param name="originalData">The password string to hash</param>
        /// <param name="salt">The salt to use</param>
        /// <returns>A hashed combination of salt and password</returns>
        string Encrypt(string originalData, string salt);

        /// <summary>
        ///     Validates the hashedPassword up agains the provided password and hash.
        /// </summary>
        /// <param name="original">The password to validate</param>
        /// <param name="salt">The salt used to created the hashedPassword</param>
        /// <param name="encrypted">The original hashed password</param>
        /// <returns>true if password corresponds to the hashed, else false</returns>
        bool Validate(string original, string salt, string encrypted);

        /// <summary>
        ///     Creates a Cryptological secure password randomly.
        /// </summary>
        /// <param name="minimumLength">The minimum lenght of the password</param>
        /// <returns>a password</returns>
        string RandomPassword(int minimumLength);

        /// <summary>
        ///     Creates a Cryptological secure password randomly using the default length defined by the
        ///     <see cref="ICryptography.MinimumSaltLength" />
        /// </summary>
        /// <returns>a password</returns>
        string RandomPassword();

        /// <summary>
        ///     Generates a random Salt with the length defined in <see cref="ICryptography.MinimumSaltLength" />c
        /// </summary>
        /// <returns>A cryptografic random Salt</returns>
        string GenerateSalt();
    }
}