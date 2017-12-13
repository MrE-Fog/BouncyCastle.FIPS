using System;

using Org.BouncyCastle.Crypto.Internal.Digests;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Generators
{ 
	/**
	 * Generator for PBE derived keys and ivs as usd by OpenSSL.
	 * <p>
	 * The scheme is a simple extension of PKCS 5 V2.0 Scheme 1 using MD5 with an
	 * iteration count of 1.
	 * </p>
	 */
	internal class OpenSslPbeParametersGenerator: PbeParametersGenerator
	{
		private readonly MD5Digest digest = new MD5Digest();

		/**
		 * Construct a OpenSSL Parameters generator. 
		 */
		public OpenSslPbeParametersGenerator()
		{
		}

		public override void Init(
			byte[]	password,
			byte[]	salt,
			int		iterationCount)
		{
			// Ignore the provided iterationCount
			base.Init(password, salt, 1);
		}

		/**
		 * Initialise - note the iteration count for this algorithm is fixed at 1.
		 * 
		 * @param password password to use.
		 * @param salt salt to use.
		 */
		public virtual void Init(
			byte[] password,
			byte[] salt)
		{
			base.Init(password, salt, 1);
		}

		/**
		 * the derived key function, the ith hash of the password and the salt.
		 */
		private byte[] GenerateDerivedKey(
			int bytesNeeded)
		{
            if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new CryptoUnapprovedOperationError("OpenSSL PBE not available in approved only mode");
            }

			byte[] buf = new byte[digest.GetDigestSize()];
			byte[] key = new byte[bytesNeeded];
			int offset = 0;
        
			for (;;)
			{
				digest.BlockUpdate(mPassword, 0, mPassword.Length);
				digest.BlockUpdate(mSalt, 0, mSalt.Length);

				digest.DoFinal(buf, 0);

				int len = (bytesNeeded > buf.Length) ? buf.Length : bytesNeeded;
				Array.Copy(buf, 0, key, offset, len);
				offset += len;

				// check if we need any more
				bytesNeeded -= len;
				if (bytesNeeded == 0)
				{
					break;
				}

				// do another round
				digest.Reset();
				digest.BlockUpdate(buf, 0, buf.Length);
			}

			return key;
		}

		/**
		 * Generate a key parameter derived from the password, salt, and iteration
		 * count we are currently initialised with.
		 *
		 * @param keySize the size of the key we want (in bits)
		 * @return a KeyParameter object.
		 * @exception ArgumentException if the key length larger than the base hash size.
		 */
		public override ICipherParameters GenerateDerivedParameters(
			int keySize)
		{
			return GenerateDerivedMacParameters(keySize);
		}

		/**
		 * Generate a key parameter for use with a MAC derived from the password,
		 * salt, and iteration count we are currently initialised with.
		 *
		 * @param keySize the size of the key we want (in bits)
		 * @return a KeyParameter object.
		 * @exception ArgumentException if the key length larger than the base hash size.
		 */
		public override ICipherParameters GenerateDerivedMacParameters(
			int keySize)
		{
			keySize = keySize / 8;

			byte[] dKey = GenerateDerivedKey(keySize);

			return new KeyParameter(dKey, 0, keySize);
		}

        public override ICipherParameters GenerateDerivedParameters(int keySize, int ivSize)
        {
            byte[] dKey = GenerateDerivedKey(keySize / 8 + ivSize / 8);

            ICipherParameters paramWithIV = new ParametersWithIV(new KeyParameter(Arrays.CopyOfRange(dKey, 0, keySize / 8)), Arrays.CopyOfRange(dKey, keySize / 8, dKey.Length));

            Arrays.Fill(dKey, 0);

            return paramWithIV;
        }

        public override ICipherParameters GenerateDerivedMacParameters(int keySize, int ivSize)
        {
            return GenerateDerivedParameters(keySize, ivSize);
        }
    }
}
