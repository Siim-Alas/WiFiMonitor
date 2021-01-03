using Microsoft.VisualStudio.TestTools.UnitTesting;
using WiFiMonitorClassLibrary.StaticHelpers;

namespace WiFiMonitorClassLibraryUnitTests.StaticHelpers
{
    [TestClass]
    public class HelperMethodsUnitTests
    {
        [TestMethod]
        public void CompareBuffers_GivenOutBuffers_WithBuffer1GreaterThanBuffer2_LesserBufferShouldReferenceEqualBuffer2AndGreaterBufferShouldReferenceEqualBuffer1()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                0, 2, 3, 4, 5, 6, 7
            };

            // Act
            HelperMethods.CompareBuffers(
                buffer1, buffer2, out byte[] lesserBuf, out byte[] greaterBuf);

            bool greaterBufIsBuffer1 = ReferenceEquals(buffer1, greaterBuf);
            bool lesserBufIsBuffer2 = ReferenceEquals(buffer2, lesserBuf);

            // Assert
            Assert.IsTrue(greaterBufIsBuffer1 && lesserBufIsBuffer2);
        }
        [TestMethod]
        public void CompareBuffers_GivenOutBuffers_WithBuffer1GreaterThanBuffer2_ShouldReturnGreaterThanZero()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                0, 2, 3, 4, 5, 6, 7
            };

            // Act
            int result = HelperMethods.CompareBuffers(
                buffer1, buffer2, out byte[] lesserBuf, out byte[] greaterBuf);

            // Assert
            Assert.IsTrue(result > 0);
        }
        [TestMethod]
        public void CompareBuffers_GivenOutBuffers_WithBuffer1LessThanBuffer2_LesserBufferShouldReferenceEqualBuffer1AndGreaterBufferShouldReferenceEqualBuffer2()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                0, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };

            // Act
            HelperMethods.CompareBuffers(
                buffer1, buffer2, out byte[] lesserBuf, out byte[] greaterBuf);

            bool lesserBufIsBuffer1 = ReferenceEquals(buffer1, lesserBuf);
            bool greaterBufIsBuffer2 = ReferenceEquals(buffer2, greaterBuf);

            // Assert
            Assert.IsTrue(lesserBufIsBuffer1 && greaterBufIsBuffer2);
        }
        [TestMethod]
        public void CompareBuffers_GivenOutBuffers_WithBuffer1LessThanBuffer2_ShouldReturnLessThanZero()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                0, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };

            // Act
            int result = HelperMethods.CompareBuffers(
                buffer1, buffer2, out byte[] lesserBuf, out byte[] greaterBuf);

            // Assert
            Assert.IsTrue(result < 0);
        }
        [TestMethod]
        public void CompareBuffers_GivenOutBuffers_WithEqualBuffers_OutBuffersShouldReferenceEqualBuffers()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };

            // Act
            HelperMethods.CompareBuffers(
                buffer1, buffer2, out byte[] lesserBuf, out byte[] greaterBuf);

            bool lesserBufIsBuffer1 = ReferenceEquals(buffer1, lesserBuf);
            bool greaterBufIsBuffer1 = ReferenceEquals(buffer1, greaterBuf);

            bool lesserBufIsBuffer2 = ReferenceEquals(buffer2, lesserBuf);
            bool greaterBufIsBuffer2 = ReferenceEquals(buffer2, greaterBuf);

            // Assert
            Assert.IsTrue((lesserBufIsBuffer1 && greaterBufIsBuffer2) || (lesserBufIsBuffer2 && greaterBufIsBuffer1));
        }
        [TestMethod]
        public void CompareBuffers_GivenOutBuffers_WithEqualBuffers_ShouldReturnZero()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };

            // Act
            int result = HelperMethods.CompareBuffers(
                buffer1, buffer2, out byte[] lesserBuf, out byte[] greaterBuf);

            // Assert
            Assert.AreEqual(0, result);
        }
        [TestMethod]
        public void CompareBuffers_WithBuffer1GreaterThanBuffer2_ShouldReturnGreaterThanZero()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                0, 2, 3, 4, 5, 6, 7
            };

            // Act
            int result = HelperMethods.CompareBuffers(buffer1, buffer2, buffer1.Length);

            // Assert
            Assert.IsTrue(result > 0);
        }
        [TestMethod]
        public void CompareBuffers_WithBuffer1LessThanBuffer2_ShouldReturnLessThanZero()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                0, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };

            // Act
            int result = HelperMethods.CompareBuffers(buffer1, buffer2, buffer1.Length);

            // Assert
            Assert.IsTrue(result < 0);
        }
        [TestMethod]
        public void CompareBuffers_WithEqualBuffers_ShouldReturnZero()
        {
            // Arrange
            byte[] buffer1 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };
            byte[] buffer2 = new byte[]
            {
                1, 2, 3, 4, 5, 6, 7
            };

            // Act
            int result = HelperMethods.CompareBuffers(buffer1, buffer2, buffer1.Length);

            // Assert
            Assert.AreEqual(0, result);
        }
    }
}
