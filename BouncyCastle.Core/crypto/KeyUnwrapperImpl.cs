using System;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class KeyUnwrapperImpl<A>: IKeyUnwrapper<A>
	{
		private readonly A parameters;
		private readonly IWrapper wrapper;

		internal KeyUnwrapperImpl (A parameters, IWrapper wrapper)
		{
			this.parameters = parameters;
			this.wrapper = wrapper;
		}

		public A AlgorithmDetails { 
			get { return parameters; }
		}

		public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
		{
			return new SimpleBlockResult (wrapper.Unwrap (cipherText, offset, length));
		}
	}
}

