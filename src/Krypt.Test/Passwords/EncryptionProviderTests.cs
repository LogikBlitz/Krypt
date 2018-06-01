using System;
using FluentAssertions;
using Krypt.Passwords;
using Moq;
using Xunit;

namespace Krypt.Test.Passwords
{
    public class EncryptionProviderTests
    {
        [Fact]
        public void Ctor_EncryptionProviderIsNull_ShouldThrow()
        {
            //ACT
            Action act = () =>  new EncryptionProvider(null);
            //ASSERT
            act.Should().Throw<ArgumentNullException>("the cryptorovider is null");
        }

        [Fact]
        public void Ctor_DefaultConstructor_ShouldNotThrow()
        {
            //ACT
            Action act = () =>  new EncryptionProvider();
            //ASSERT
            act.Should().NotThrow("the default ctor instanciates with default cryptoprovider");
            
        }

        [Fact]
        public void Encrypt_ShouldUseProvidedCryptography()
        {
            //ARRANGE
            var cryptoMock = new Mock<ICryptography>(MockBehavior.Strict);
            var mockHash = "FooBar";
            cryptoMock.Setup(c => c.MinimumSaltLength).Returns(mockHash.Length);
            cryptoMock.Setup(c => c.ComputeHash(It.IsAny<string>())).Returns(mockHash);
            const string originalData = "Mjello";

            //ACT
            var provider = new EncryptionProvider(cryptoMock.Object);
            var salt = provider.GenerateSalt();
            var encrypted = provider.Encrypt(originalData, salt);

            //ASSERT
            mockHash.Should().Be(encrypted);
        }

        [Fact]
        public void Validate_EncryptedPasswordAndSald_ShouldValidatePasswordUsingSalt()
        {
            //ARRANGE
            const string originalData = "Mjello";
            const string salt = "foobar123";

            //ACT
            var provider = new EncryptionProvider();
            var encrypted = provider.Encrypt(originalData, salt);

            var isValid = provider.Validate(originalData, salt, encrypted);
            //ASSERT
            originalData.Should().NotBe(encrypted);
            isValid.Should().BeTrue();
        }

        [Fact]
        public void Salt_LengthOfSalt_ShouldBeGreaterThanOrEqualToRecommendedSaltLength()
        {
            //ARRANGE
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);

            //ACT
            var salt = provider.GenerateSalt();

            //ASSERT
            salt.Length.Should().BeGreaterOrEqualTo(crypto.MinimumSaltLength, $"The lenght of the generated salt is not of correct length. Expected: saltlength: {salt.Length} >= {crypto.MinimumSaltLength}");
              }

        [Fact]
        public void Password_Random_ShouldGenerateRandomPassword()
        {
            //ARRANGE
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);

            //ACT
            var password = provider.RandomPassword();

            //ASSERT
            password.Length.Should().BeGreaterOrEqualTo(crypto.MinimumSaltLength);
              }

        [Fact]
        public void Password_RandomWithMinimumLength_ShouldGenerateRandomPassword()
        {
            //ARRANGE
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);
            const int minimumLength = 2;

            //ACT
            var password = provider.RandomPassword(minimumLength);

            //ASSERT
            password.Length.Should().BeGreaterOrEqualTo(minimumLength);          
            
        }

        [Fact]
        public void Password_MinimumLengthEqualZero_ShouldThrow()
        {
            //ARRANGE
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);
            const int minimumLength = 0;

            //ACT 
            Action act = () => provider.RandomPassword(minimumLength);
            
            //ASSERT
            act.Should().Throw<ArgumentException>();

        }

        [Fact]
        public void Password_MinimumLengthLessThanZero_ShouldThrow()
        {
            //SETUP
            var crypto = new CryptographySha512();
            var provider = new EncryptionProvider(crypto);
            const int minimumLength = -1;

            //ACT
            Action act = () => provider.RandomPassword(minimumLength);
            
            //ASSERT
            act.Should().Throw<ArgumentException>("the length of the password must be greater than zero");
        }
    }
}