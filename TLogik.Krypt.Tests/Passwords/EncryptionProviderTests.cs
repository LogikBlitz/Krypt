using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using TLogik.Krypt.Passwords;

namespace TLogik.Krypt.Tests.Passwords
{
    [TestClass()]
    public class EncryptionProviderTests
    {
        [TestMethod, TestCategory("Unit")]
        [ExpectedException(typeof (ArgumentNullException))]
        public void Ctor_EncryptionProviderIsNull_ShouldThrow()
        {
            var provider = new EncryptionProvider(null);
        }

        [TestMethod, TestCategory("Unit")]
        public void Ctor_DefaultConstructor_ShouldNotThrow()
        {
            var provider = new EncryptionProvider();
        }

        [TestMethod, TestCategory("Unit")]
        public void Encrypt_ShouldUseProvidedCryptography()
        {
            //SETUP
            var cryptoMock = new Mock<ICryptography>(MockBehavior.Strict);
            var mockHash = "FooBar";
            cryptoMock.Setup(c => c.MinimumSaltLength).Returns(mockHash.Length);
            cryptoMock.Setup(c => c.ComputeHash(It.IsAny<string>())).Returns(mockHash);
            const string originalData = "Mjello";

            //EXECUTE
            var provider = new EncryptionProvider(cryptoMock.Object);
            var salt = provider.GenerateSalt();
            var encrypted = provider.Encrypt(originalData, salt);

            //ASSERT
            Assert.AreEqual(mockHash, encrypted);
        }

        [TestMethod, TestCategory("Unit")]
        public void Validate_EncryptedPasswordAndSald_ShouldValidatePasswordUsingSalt()
        {
            //SETUP
            const string originalData = "Mjello";
            const string salt = "foobar123";

            //EXECUTE
            var provider = new EncryptionProvider();
            var encrypted = provider.Encrypt(originalData, salt);
            Assert.AreNotEqual(originalData, encrypted);

            var areEqual = provider.Validate(originalData, salt, encrypted);
            //ASSERT
            Assert.IsTrue(areEqual);
        }

        [TestMethod, TestCategory("Unit")]
        public void Salt_LengthOfSalt_ShouldBeGreaterThanOrEqualToRecommendedSaltLength()
        {
            //SETUP
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);

            //EXECUTE
            var salt = provider.GenerateSalt();

            //ASSERT
            Assert.IsTrue(salt.Length >= crypto.MinimumSaltLength,
                $"The lenght of the generated salt is not of correct length. Expected: saltlength: {salt.Length} >= {crypto.MinimumSaltLength}");
        }

        [TestMethod, TestCategory("Unit")]
        public void Password_Random_ShouldGenerateRandomPassword()
        {
            //SETUP
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);

            //EXECUTE
            var password = provider.RandomPassword();

            //ASSERT
            Assert.IsTrue(password.Length >= crypto.MinimumSaltLength,
                $"The lenght of the generated password is not of correct length. Expected: saltlength: {password.Length} >= {crypto.MinimumSaltLength}");
        }

        [TestMethod, TestCategory("Unit")]
        public void Password_RandomWithMinimumLength_ShouldGenerateRandomPassword()
        {
            //SETUP
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);
            const int minimumLength = 2;

            //EXECUTE
            var password = provider.RandomPassword(minimumLength);

            //ASSERT
            Assert.IsTrue(password.Length >= minimumLength,
                $"The lenght of the generated password is not of correct length. Expected: saltlength: {password.Length} >= {minimumLength}");
        }

        [TestMethod, TestCategory("Unit")]
        [ExpectedException(typeof (ArgumentException))]
        public void Password_MinimumLengthEqualZero_ShouldThrow()
        {
            //SETUP
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);
            const int minimumLength = 0;

            //EXECUTE
            var password = provider.RandomPassword(minimumLength);
        }

        [TestMethod, TestCategory("Unit")]
        [ExpectedException(typeof (ArgumentException))]
        public void Password_MinimumLengthLessThanZero_ShouldThrow()
        {
            //SETUP
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);
            const int minimumLength = -1;

            //EXECUTE
            var password = provider.RandomPassword(minimumLength);
        }
    }
}