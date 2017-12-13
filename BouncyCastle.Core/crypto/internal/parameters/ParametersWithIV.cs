using System;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class ParametersWithIV
		: ICipherParameters
    {
        internal static ICipherParameters ApplyOptionalIV(ICipherParameters parameters, byte[] iv)
        {
            return iv == null ? parameters : new ParametersWithIV(parameters, iv);
        }

        private readonly ICipherParameters	parameters;
		private readonly byte[]				iv;

		internal ParametersWithIV(
            ICipherParameters	parameters,
            byte[]				iv)
			: this(parameters, iv, 0, (iv == null ? -1 : iv.Length))
		{
        }

		internal ParametersWithIV(
            ICipherParameters	parameters,
            byte[]				iv,
            int					ivOff,
            int					ivLen)
        {
            // NOTE: 'parameters' may be null to imply key re-use
			if (iv == null)
				throw new ArgumentNullException("iv");

			this.parameters = parameters;
			this.iv = new byte[ivLen];
            Array.Copy(iv, ivOff, this.iv, 0, ivLen);
        }

		public byte[] GetIV()
        {
			return (byte[]) iv.Clone();
        }

		internal ICipherParameters Parameters
        {
            get { return parameters; }
        }
    }
}
