using System;
using System.IO;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;


namespace Org.BouncyCastle.Utilities.Test
{
    /// <summary>
    ///  A secure random that returns pre-seeded data to calls of NextBytes() or GenerateSeed().
    /// </summary>
    public class FixedSecureRandom: SecureRandom
	{
		private byte[]       _data;

		private int          _index;

		/// <summary>
		/// Base class for sources of fixed "Randomness".
		/// </summary>
		public class Source
		{
			internal byte[] data;

			protected Source(byte[] data)
			{
				this.data = data;
			}
		}
			
		/// <summary>
		/// Data Source - in this case we just expect requests for byte arrays.
		/// </summary>
		public class Data: Source
		{
			public Data(byte[] data): base(data)
			{
			}
		}
			
		/// <summary>
		/// BigInteger Source - in this case we expect requests for data that will be used
		/// for BigIntegers. The FixedSecureRandom will attempt to compensate for platform differences here.
		/// </summary>
		public class BigInteger: Source
		{
			public BigInteger(byte[] data): base(data)
			{
			}

			public BigInteger(String hexData): base(Hex.Decode(hexData))
			{
			}
		}

		public FixedSecureRandom(
			params Source[] sources)
		{
			MemoryStream bOut = new MemoryStream();

			for (int i = 0; i != sources.Length; i++)
			{
				try
				{
					bOut.Write(sources[i].data, 0, sources[i].data.Length);
				}
				catch (IOException e)
				{
					throw new ArgumentException("can't save value source.", e);
				}
			}

			_data = bOut.ToArray();
		}

		public override void NextBytes(byte[] bytes)
		{
			Array.Copy(_data, _index, bytes, 0, bytes.Length);

			_index += bytes.Length;
		}

		public override byte[] GenerateSeed(int numBytes)
		{
			byte[] bytes = new byte[numBytes];

			this.NextBytes(bytes);

			return bytes;
		}

		//
		// classpath's implementation of SecureRandom doesn't currently go back to nextBytes
		// when next is called. We can't override next as it's a final method.
		//
		public override int NextInt()
		{
			int val = 0;

			val |= nextValue() << 24;
			val |= nextValue() << 16;
			val |= nextValue() << 8;
			val |= nextValue();

			return val;
		}

		//
		// classpath's implementation of SecureRandom doesn't currently go back to nextBytes
		// when next is called. We can't override next as it's a final method.
		//
		public override long NextLong()
		{
			long val = 0;

			val |= (long)nextValue() << 56;
			val |= (long)nextValue() << 48;
			val |= (long)nextValue() << 40;
			val |= (long)nextValue() << 32;
			val |= (long)nextValue() << 24;
			val |= (long)nextValue() << 16;
			val |= (long)nextValue() << 8;
			val |= (long)nextValue();

			return val;
		}

		public bool IsExhausted()
		{
			return _index == _data.Length;
		}

		private int nextValue()
		{
			return _data[_index++] & 0xff;
		}

		private class RandomChecker: SecureRandom
		{
			internal RandomChecker()
			{
			}

			byte[] data = Hex.Decode("01020304ffffffff0506070811111111");
			int    index = 0;

			public void nextBytes(byte[] bytes)
			{
				Array.Copy(data, index, bytes, 0, bytes.Length);

				index += bytes.Length;
			}
		}
	}
}

