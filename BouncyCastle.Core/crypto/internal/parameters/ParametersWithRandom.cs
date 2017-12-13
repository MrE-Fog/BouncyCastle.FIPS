using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class ParametersWithRandom
		: ICipherParameters
    {
        private readonly ICipherParameters	parameters;
		private readonly SecureRandom		random;

		internal ParametersWithRandom(
            ICipherParameters	parameters,
            SecureRandom		random)
        {
			if (parameters == null)
				throw new ArgumentNullException("parameters");
			if (random == null)
				throw new ArgumentNullException("random");

			this.parameters = parameters;
			this.random = random;
		}

		internal ParametersWithRandom(
            ICipherParameters parameters)
			: this(parameters, CryptoServicesRegistrar.GetSecureRandom())
        {
		}

        public SecureRandom Random
        {
			get { return random; }
        }

		internal ICipherParameters Parameters
        {
            get { return parameters; }
        }
    }
}
