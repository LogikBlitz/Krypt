using System;
using FluentAssertions;
using Xunit;

// ReSharper disable once CheckNamespace
namespace System.Text.Cryptography.Test
{
    public class StringCryptographyTests

    {
        private const string CipherKey = "E546C8DF278CD5931069B522E695D4F2dkjghdfsbgfnsdmgfs89398472394kjsdhf";
        [Fact]
        public void EncryptString()
        {
            
            //ARRANGE
            const string input = "Example Test#sdfdsfdsfdsfdsfret";
            var cipherKey = StringCryptography.GenerateCipherKey();
            //ACT
            var cipher = input.Encrypt(cipherKey);
            var decrypted = cipher.Dencrypt(cipherKey);
            //ASSERT
            cipher.Should().NotBeNullOrEmpty();
            cipher.Should().NotBe(input);
            decrypted.Should().Be(input);
        }
    }
}