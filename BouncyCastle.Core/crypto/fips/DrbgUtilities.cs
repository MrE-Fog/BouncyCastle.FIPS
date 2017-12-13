using System;
using System.Collections;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Fips
{
	internal class DrbgUtilities
	{
		private static readonly IDictionary maxSecurityStrengths = Platform.CreateHashtable();

        static DrbgUtilities()
	    {
	        maxSecurityStrengths.Add("SHA-1", 128);

	        maxSecurityStrengths.Add("SHA-224", 192);
	        maxSecurityStrengths.Add("SHA-256", 256);
	        maxSecurityStrengths.Add("SHA-384", 256);
	        maxSecurityStrengths.Add("SHA-512", 256);

	        maxSecurityStrengths.Add("SHA-512/224", 192);
	        maxSecurityStrengths.Add("SHA-512/256", 256);
	    }

        internal static int GetMaxSecurityStrength(IDigest d)
	    {
	        return (int)maxSecurityStrengths[d.AlgorithmName];
	    }

        internal static int GetMaxSecurityStrength(IMac m)
	    {
	        string name = m.AlgorithmName;

            return (int)maxSecurityStrengths[name.Substring(0, name.IndexOf("/"))];
	    }

	    /**
	     * Used by both Dual EC and Hash.
	     */
	    internal static byte[] HashDF(IDigest digest, byte[] seedMaterial, int seedLength)
	    {
	         // 1. temp = the Null string.
	        // 2. .
	        // 3. counter = an 8-bit binary value representing the integer "1".
	        // 4. For i = 1 to len do
	        // Comment : In step 4.1, no_of_bits_to_return
	        // is used as a 32-bit string.
	        // 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
	        // input_string).
	        // 4.2 counter = counter + 1.
	        // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
	        // 6. Return SUCCESS and requested_bits.
	        byte[] temp = new byte[(seedLength + 7) / 8];

	        int len = temp.Length / digest.GetDigestSize();
	        int counter = 1;

	        byte[] dig = new byte[digest.GetDigestSize()];

	        for (int i = 0; i <= len; i++)
	        {
	            digest.Update((byte)counter);

	            digest.Update((byte)(seedLength >> 24));
	            digest.Update((byte)(seedLength >> 16));
	            digest.Update((byte)(seedLength >> 8));
	            digest.Update((byte)seedLength);

	            digest.BlockUpdate(seedMaterial, 0, seedMaterial.Length);

	            digest.DoFinal(dig, 0);

	            int bytesToCopy = ((temp.Length - i * dig.Length) > dig.Length)
	                    ? dig.Length
	                    : (temp.Length - i * dig.Length);
	            Array.Copy(dig, 0, temp, i * dig.Length, bytesToCopy);

	            counter++;
	        }

	        // do a left shift to get rid of excess bits.
	        if (seedLength % 8 != 0)
	        {
	            int shift = 8 - (seedLength % 8);
	            uint carry = 0;

                for (int i = 0; i != temp.Length; i++)
	            {
	                uint b = temp[i];
	                temp[i] = (byte)((b >> shift) | (carry << (8 - shift)));
	                carry = b;
	            }
	        }

            return temp;
	    }

        internal static bool IsTooLarge(byte[] bytes, int maxBytes)
	    {
	        return bytes != null && bytes.Length > maxBytes;
	    }

		/// <summary>
		/// Lying entropy source for self testing
		/// </summary>
		internal class LyingEntropySource: IEntropySource
		{
			private readonly int entropySize;

			internal LyingEntropySource(int entropySize)
			{
				this.entropySize = entropySize;
			}

			public bool IsPredictionResistant
			{
				get {
					return false;
				}
			}

			public byte[] GetEntropy()
			{
				return new byte[2];
			}

			public int EntropySize
			{
				get {
					return entropySize;
				}
			}
		}

		// for self testing
		internal class KatEntropyProvider: DrbgKatFixedEntropySourceProvider
        {
			internal KatEntropyProvider () : base (
					Hex.Decode (
						"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
						"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
						"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
						"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
						"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
						"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
						"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
						"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" +
						"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
						"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
						"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
						"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
						"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
						"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
						"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
						"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), true)
			{
			}
		}
	}
}
