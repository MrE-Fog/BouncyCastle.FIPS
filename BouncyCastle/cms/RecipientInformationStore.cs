using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.X500;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// A store collection class for RecipientInformation objects.
    /// </summary>
    public class RecipientInformationStore : IStore<RecipientInformation>
    {
        private readonly IList<RecipientInformation> all; //ArrayList[RecipientInformation]
        private readonly IDictionary table = Platform.CreateHashtable(); // Hashtable[RecipientID, ArrayList[RecipientInformation]]

        /// <summary>
        /// Create a store containing a collection of RecipientInformation objects.
        /// </summary>
        /// <param name="recipientInfos">A collection of recipient information objects to contain.</param>
        public RecipientInformationStore(
            ICollection<RecipientInformation> recipientInfos)
        {
            foreach (RecipientInformation recipientInfo in recipientInfos)
            {
                IRecipientID<RecipientInformation> rid = recipientInfo.RecipientID;
                IList<RecipientInformation> list = (IList<RecipientInformation>)table[rid];

                if (list == null)
                {
                    table[rid] = list = new List<RecipientInformation>();
                }

                list.Add(recipientInfo);
            }

            this.all = new List<RecipientInformation>(recipientInfos);
        }

        public RecipientInformation this[IRecipientID<RecipientInformation> selector]
        {
            get { return GetFirstMatch(selector); }
        }

        /**
		* Return the first RecipientInformation object that matches the
		* passed in selector. Null if there are no matches.
		*
		* @param selector to identify a recipient
		* @return a single RecipientInformation object. Null if none matches.
		*/
        public RecipientInformation GetFirstMatch(
            IRecipientID<RecipientInformation> selector)
        {
            ICollection<RecipientInformation> res = GetMatches(selector);

            if (res.Count == 0)
            {
                return null;
            }

            IEnumerator<RecipientInformation> en = res.GetEnumerator();

            en.MoveNext();

            return en.Current;
        }

        /**
		* Return the number of recipients in the collection.
		*
		* @return number of recipients identified.
		*/
        public int Count
        {
            get { return all.Count; }
        }

        /**
		* Return all recipients in the collection
		*
		* @return a collection of recipients.
		*/
        public ICollection<RecipientInformation> GetAll()
        {
            return new List<RecipientInformation>(all);
        }

        /**
		* Return possible empty collection with recipients matching the passed in RecipientID
		*
		* @param selector a recipient id to select against.
		* @return a collection of RecipientInformation objects.
		*/
        public ICollection<RecipientInformation> GetMatches(ISelector<RecipientInformation> selector)
        {
            if (selector is KeyTransRecipientID)
            {
                KeyTransRecipientID keyTrans = (KeyTransRecipientID)selector;

                X500Name issuer = keyTrans.Issuer;
                byte[] subjectKeyId = keyTrans.GetSubjectKeyIdentifier();

                if (issuer != null && subjectKeyId != null)
                {
                    IList<RecipientInformation> results = new List<RecipientInformation>();

                    ICollection<RecipientInformation> match1 = GetMatches(new KeyTransRecipientID(issuer, keyTrans.SerialNumber));
                    if (match1 != null)
                    {
                        for (IEnumerator<RecipientInformation> en = match1.GetEnumerator(); en.MoveNext();)
                        {
                            results.Add(en.Current);
                        }
                    }

                    ICollection<RecipientInformation> match2 = GetMatches(new KeyTransRecipientID(subjectKeyId));
                    if (match2 != null)
                    {
                        for (IEnumerator<RecipientInformation> en = match2.GetEnumerator(); en.MoveNext();)
                        {
                            results.Add(en.Current);
                        }
                    }

                    return results;
                }
            }

            IList<RecipientInformation> list = (IList<RecipientInformation>)table[selector];
        
            return list == null ? new List<RecipientInformation>(0) : new List<RecipientInformation>(list);
        }
    }
}
