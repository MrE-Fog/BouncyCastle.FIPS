using System;

namespace Org.BouncyCastle.Crypto
{
	using Org.BouncyCastle.Crypto.Internal;

	internal class KeyWrapperImpl<A>: IKeyWrapper<A>
	{
		private readonly A parameters;
		private readonly IWrapper wrapper;

		internal KeyWrapperImpl (A parameters, IWrapper wrapper)
		{
			this.parameters = parameters;
			this.wrapper = wrapper;
		}

		public A AlgorithmDetails { 
			get { return parameters; }
		}

		public IBlockResult Wrap(byte[] keyData)
		{
			return new SimpleBlockResult (wrapper.Wrap (keyData, 0, keyData.Length));
		}
	}
}

