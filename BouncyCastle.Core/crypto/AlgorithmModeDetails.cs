
using System.Collections;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
	internal class AlgorithmModeDetails
	{
		private static readonly IDictionary detailsTable = Platform.CreateHashtable();

		private readonly AlgorithmMode mode;
		private readonly string code;
		private readonly bool expectsIV;

		private AlgorithmModeDetails (AlgorithmMode mode, string code, bool expectsIV)
		{
			this.mode = mode;
			this.code = code;
			this.expectsIV = expectsIV;
		}

		public AlgorithmMode Mode { get { return mode; } }

		public string Code { get { return code; } }

		public bool ExpectsIV { get { return expectsIV; } }

		static AlgorithmModeDetails()
		{
            detailsTable.Add(AlgorithmMode.CBC, new AlgorithmModeDetails(AlgorithmMode.CBC, "CBC", true));
            detailsTable.Add(AlgorithmMode.CFB8, new AlgorithmModeDetails(AlgorithmMode.CFB8, "CFB8", true));
            detailsTable.Add(AlgorithmMode.CFB64, new AlgorithmModeDetails(AlgorithmMode.CFB64, "CFB64", true));
            detailsTable.Add(AlgorithmMode.CFB128, new AlgorithmModeDetails(AlgorithmMode.CFB128, "CFB128", true));
            detailsTable.Add(AlgorithmMode.OFB128, new AlgorithmModeDetails(AlgorithmMode.CBC, "OFB128", true));
            detailsTable.Add(AlgorithmMode.OFB64, new AlgorithmModeDetails(AlgorithmMode.CBC, "OFB64", true));
            detailsTable.Add(AlgorithmMode.CTR, new AlgorithmModeDetails(AlgorithmMode.CTR, "CTR", true));
            detailsTable.Add(AlgorithmMode.CCM, new AlgorithmModeDetails(AlgorithmMode.CCM, "CCM", true));
            detailsTable.Add(AlgorithmMode.GCM, new AlgorithmModeDetails(AlgorithmMode.GCM, "GCM", true));
            detailsTable.Add(AlgorithmMode.GMAC, new AlgorithmModeDetails(AlgorithmMode.GMAC, "GMAC", true));
        }

		internal static AlgorithmModeDetails GetDetails(AlgorithmMode mode)
		{
			return (AlgorithmModeDetails)detailsTable[mode];
		}

	}
}

