
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Parameters;

namespace Org.BouncyCastle.Crypto
{
	internal class PasswordBasedDeriver<A>: IPasswordBasedDeriver<A>
	{
        private readonly bool approvedOnlyMode;
		private readonly A algorithmDetails;
		private readonly PbeParametersGenerator generator;

		public PasswordBasedDeriver (A algorithmDetails, PbeParametersGenerator generator)
		{
            this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithmDetails = algorithmDetails;
			this.generator = generator;
		}
			
		public A AlgorithmDetails { get { return algorithmDetails; } }

		public byte[] DeriveKey(TargetKeyType keyType, int keySizeInBytes)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "PasswordBasedDeriver");

            if (approvedOnlyMode)
            {
                if (keySizeInBytes < 14)
                {
                    throw new CryptoUnapprovedOperationError("keySizeInBytes must be at least 14");
                }
            }

			if (keyType == TargetKeyType.MAC) {
				return ((KeyParameter)generator.GenerateDerivedMacParameters(keySizeInBytes * 8)).GetKey();
			}

			return ((KeyParameter)generator.GenerateDerivedParameters(keySizeInBytes * 8)).GetKey();
		}
			
		public byte[][] DeriveKeyAndIV(TargetKeyType keyType, int keySizeInBytes, int ivSizeInBytes)
		{
            CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "PasswordBasedDeriver");

            if (approvedOnlyMode)
            {
                if (keySizeInBytes < 14)
                {
                    throw new CryptoUnapprovedOperationError("keySizeInBytes must be at least 14");
                }
            }

            if (keyType == TargetKeyType.MAC)
            {
                ParametersWithIV paramWithIv = (ParametersWithIV)generator.GenerateDerivedMacParameters(keySizeInBytes * 8, ivSizeInBytes * 8);

                return new byte[][] { ((KeyParameter)paramWithIv.Parameters).GetKey(), paramWithIv.GetIV() };
            }
            else
            {
                ParametersWithIV paramWithIv = (ParametersWithIV)generator.GenerateDerivedParameters(keySizeInBytes * 8, ivSizeInBytes * 8);

                return new byte[][] { ((KeyParameter)paramWithIv.Parameters).GetKey(), paramWithIv.GetIV() };
            }
		}
	}
}

