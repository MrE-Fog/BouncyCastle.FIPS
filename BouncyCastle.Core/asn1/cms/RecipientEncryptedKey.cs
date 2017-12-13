using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
	public class RecipientEncryptedKey
		: Asn1Encodable
	{
		private readonly KeyAgreeRecipientIdentifier identifier;
		private readonly Asn1OctetString encryptedKey;

		private RecipientEncryptedKey(
			Asn1Sequence seq)
		{
			identifier = KeyAgreeRecipientIdentifier.GetInstance(seq[0]);
			encryptedKey = (Asn1OctetString) seq[1];
		}

		/**
		 * return an RecipientEncryptedKey object from a tagged object.
		 *
		 * @param obj the tagged object holding the object we want.
		 * @param isExplicit true if the object is meant to be explicitly
		 *              tagged false otherwise.
		 * @exception ArgumentException if the object held by the
		 *          tagged object cannot be converted.
		 */
		public static RecipientEncryptedKey GetInstance(
			Asn1TaggedObject	obj,
			bool				isExplicit)
		{
			return GetInstance(Asn1Sequence.GetInstance(obj, isExplicit));
		}

		/**
		 * return a RecipientEncryptedKey object from the given object.
		 *
		 * @param obj the object we want converted.
		 * @exception ArgumentException if the object cannot be converted.
		 */
		public static RecipientEncryptedKey GetInstance(
			object obj)
		{
            if (obj is RecipientEncryptedKey)
                return (RecipientEncryptedKey)obj;

            if (obj != null)
                return new RecipientEncryptedKey(Asn1Sequence.GetInstance(obj));

            return null;
        }

		public RecipientEncryptedKey(
			KeyAgreeRecipientIdentifier	id,
			Asn1OctetString				encryptedKey)
		{
			this.identifier = id;
			this.encryptedKey = encryptedKey;
		}

		public KeyAgreeRecipientIdentifier Identifier
		{
			get { return identifier; }
		}

		public Asn1OctetString EncryptedKey
		{
			get { return encryptedKey; }
		}

		/** 
		 * Produce an object suitable for an Asn1OutputStream.
		 * <pre>
		 * RecipientEncryptedKey ::= SEQUENCE {
		 *     rid KeyAgreeRecipientIdentifier,
		 *     encryptedKey EncryptedKey
		 * }
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(identifier, encryptedKey);
		}
	}
}
