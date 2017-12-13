
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Cert
{
	public abstract class X509ExtensionBase
	{
		protected abstract X509Extensions Extensions { get; }

		protected virtual ISet GetExtensionOids(
			bool critical)
		{
			X509Extensions extensions = Extensions;
			if (extensions != null)
			{
				HashSet set = new HashSet();
				foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
				{
					X509Extension ext = extensions.GetExtension(oid);
					if (ext.IsCritical == critical)
					{
						set.Add(oid);
					}
				}

				return set;
			}

			return null;
		}

		/// <summary>
		/// Get non critical extensions.
		/// </summary>
		/// <returns>A set of non critical extension oids.</returns>
		public virtual ISet GetNonCriticalExtensionOids()
		{
			return GetExtensionOids(false);
		}

        /// <summary>
        /// Get any critical extensions.
        /// </summary>
        /// <returns>A set of critical extension oids.</returns>
        public virtual ISet GetCriticalExtensionOids()
		{
			return GetExtensionOids(true);
		}

        /// <summary>
        /// Get the value of a given extension.
        /// </summary>
        /// <param name="oid">The object ID of the extension. </param>
        /// <returns>An Asn1OctetString object if that extension is found or null if not.</returns>
        public virtual byte[] GetExtensionValue(
			DerObjectIdentifier oid)
		{
			X509Extensions exts = Extensions;
			if (exts != null)
			{
				X509Extension ext = exts.GetExtension(oid);
				if (ext != null)
				{
					return Arrays.Clone(ext.Value.GetOctets());
				}
			}

			return null;
		}
	}
}
