using System;

namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Base interface for factories that produce stream-based signature verifiers which are only
    /// valid within a particular date range.
    /// </summary>
    /// <typeparam name="A">Configuration parameters type for the verifiers.</typeparam>
    public interface IDatedVerifierFactory<out A>: IVerifierFactory<A>
    {
        /// <summary>
        /// Return true if this verify is valid at the passed in time.
        /// </summary>
        /// <param name="dateTime">The date/time to check validity of the verifier at.</param>
        /// <returns>true if a signature at dateTime is valid, false otherwise.</returns>
        bool IsValidAt(DateTime dateTime);
    }
}
