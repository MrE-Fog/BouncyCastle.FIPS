using System;

namespace Org.BouncyCastle.Crypto
{
	/// <summary>
	/// Interface to SP800-90A/X9.31 deterministic random bit generators.
	/// </summary>
	internal interface IDrbg
	{
		/// <summary>
		/// Return the block size of the DRBG.
		/// </summary>
		/// <value>The block size (in bits) produced by each round of the DRBG.</value>
		int BlockSize { get; }

		/// <summary>
		/// Return the security strength of the DRBG.
		/// </summary>
		/// <value>The security strength (in bits) of the DRBG.</value>
		int SecurityStrength { get; }

		/// <summary>
		/// Populate a passed in array with random data.
		/// </summary>
		/// <param name="output">Output array for generated bits.</param>
		/// <param name="additionalInput">Additional input to be added to the DRBG in this step.</param>
		/// <param name="predictionResistant"><c>true</c> if a reseed should be forced, <c>false</c> otherwise.</param>
		/// <returns>number of bits generated, -1 if a reseed required.</returns>
		int Generate(byte[] output, byte[] additionalInput, bool predictionResistant);

		/// <summary>
		/// Reseed the DRBG.
		/// </summary>
		/// <param name="additionalInput">Additional input to be added to the DRBG in this step.</param>
		void Reseed(byte[] additionalInput);

		/// <summary>
		/// Return a KAT for the DRBG - used prior to initialisation.
		/// </summary>
		/// <returns>A self test</returns>
		/// <param name="algorithm">The algorithm type</param>
		VariantInternalKatTest CreateSelfTest(Algorithm algorithm);

		/// <summary>
		/// Return a KAT for the DRBG - used prior to reseed.
		/// </summary>
		/// <returns>A reseed self test</returns>
		/// <param name="algorithm">The algorithm type</param>
		VariantInternalKatTest CreateReseedSelfTest(Algorithm algorithm);
	}

}

