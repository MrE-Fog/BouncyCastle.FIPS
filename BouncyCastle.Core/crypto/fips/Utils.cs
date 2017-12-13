using System;

using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Fips
{
	internal class Utils
	{
		internal Utils ()
		{
		}

        // TODO: should be FIPS
		internal static SecureRandom testRandom = new SecureRandom();

		internal static void ValidateRandom(SecureRandom random, String message)
		{
			if (!(random is FipsSecureRandom))
			{
				throw new CryptoUnapprovedOperationError(message);
			}
		}

		internal static void ValidateRandom(SecureRandom random, int securityStrength, FipsAlgorithm algorithm, String message)
		{
			if (random is FipsSecureRandom)
			{
				if (((FipsSecureRandom)random).SecurityStrength < securityStrength)
				{
					throw new CryptoUnapprovedOperationError("FIPS SecureRandom security strength not as high as required for operation", algorithm);
				}
			}
			else
			{
				throw new CryptoUnapprovedOperationError(message, algorithm);
			}

		}

		internal static void ValidateKeyGenRandom(SecureRandom random, int securityStrength, FipsAlgorithm algorithm)
		{
			ValidateRandom(random, securityStrength, algorithm, "attempt to create key with unapproved RNG");
		}

		internal static void ValidateKeyPairGenRandom(SecureRandom random, int securityStrength, FipsAlgorithm algorithm)
		{
			ValidateRandom(random, securityStrength, algorithm, "attempt to create key pair with unapproved RNG");
		}

		internal static int GetAsymmetricSecurityStrength(int sizeInBits)
		{
			if (sizeInBits >= 15360)
			{
				return 256;
			}
			if (sizeInBits >= 7680)
			{
				return 192;
			}
			if (sizeInBits >= 3072)
			{
				return 128;
			}
			if (sizeInBits >= 2048)
			{
				return 112;
			}
			if (sizeInBits >= 1024)
			{
				return 80;
			}

			throw new CryptoOperationError("requested security strength unknown");
		}

		public static int GetECCurveSecurityStrength(ECCurve curve)
		{
			int fieldSizeInBits = curve.FieldSize;

			if (fieldSizeInBits >= 512)
			{
				return 256;
			}
			if (fieldSizeInBits >= 384)
			{
				return 192;
			}
			if (fieldSizeInBits >= 256)
			{
				return 128;
			}
			if (fieldSizeInBits >= 224)
			{
				return 112;
			}
			if (fieldSizeInBits >= 160)
			{
				return 80;
			}

			throw new CryptoOperationError("Requested security strength unknown");
		}

	}
}

