using System;
using System.IO;

namespace Org.BouncyCastle.Crypto
{
	public interface IVariableStreamCalculator<out TResult>: IStreamCalculator<TResult>
	{
		/// <summary>
		/// Return a result of processing the stream with a specified length. This value is only available once the stream
		/// has been closed.
		/// </summary>
		/// <returns>The result.</returns>
		/// <param name="outputLength">The length of the result expected in the result object.</param>
		TResult GetResult(int outputLength);
	}
}

