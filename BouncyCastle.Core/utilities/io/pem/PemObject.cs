using System;
using System.Collections;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
    /// <summary>
    /// A generic PEM object type.
    /// </summary>
	public class PemObject
		: PemObjectGenerator
	{
		private readonly string		type;
		private readonly IList		headers;
		private readonly byte[]		content;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="type">The type of the PEM object.</param>
        /// <param name="content">The byte content it contains.</param>
		public PemObject(string type, byte[] content)
			: this(type, Platform.CreateArrayList(), content)
		{
		}

        /// <summary>
        /// Constructor with headers.
        /// </summary>
        /// <param name="type">The type of the PEM object.</param>
        /// <param name="headers">A list of headers in the object.</param>
        /// <param name="content">The byte content it contains.</param>
		public PemObject(String type, IList headers, byte[] content)
		{
			this.type = type;
            this.headers = Platform.CreateArrayList(headers);
			this.content = content;
		}

        /// <summary>
        /// Return the type of the PEM object.
        /// </summary>
		public string Type
		{
			get { return type; }
		}

        /// <summary>
        /// Return a list of the headers in the PEM object.
        /// </summary>
		public IList Headers
		{
			get { return headers; }
		}

        /// <summary>
        /// Return the raw content in the object.
        /// </summary>
        /// <returns>The content of the PEM object.</returns>
		public byte[] GetContent()
		{
			return Arrays.Clone(content); 
		}

        /// <summary>
        /// Generate a PemObject from this one.
        /// </summary>
        /// <returns>this</returns>
		public PemObject Generate()
		{
			return this;
		}
	}
}
