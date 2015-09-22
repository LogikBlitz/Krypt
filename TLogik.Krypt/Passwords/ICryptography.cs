namespace TLogik.Krypt.Passwords
{
    /// <summary>
    ///     Defines simple methods for creating cryptographically safe hashes.
    /// </summary>
    public interface ICryptography
    {
        /// <summary>
        ///     Computes a secure hash from the input data.
        /// </summary>
        /// <param name="data">The data to hash</param>
        /// <returns>The hashvalue created from the <see cref="data" /></returns>
        string ComputeHash(string data);

        /// <summary>
        ///     Provides info on the complexity of the algorithms output fron <see cref="ComputeHash" />.
        ///     Basically it provides a hint on hos long the output is in regards
        ///     to creating minimum salting that relate to the hashing
        /// </summary>
        int MinimumSaltLength { get; }
    }
}