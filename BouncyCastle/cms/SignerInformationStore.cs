
using System.Collections;

using Org.BouncyCastle.Utilities;
using System.Collections.Generic;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// A store collection class for SignerInformation objects.
    /// </summary>
    public class SignerInformationStore: IStore<SignerInformation>
    {
        private readonly IList<SignerInformation> all; //ArrayList[SignerInformation]
        private readonly IDictionary table = Platform.CreateHashtable(); // Hashtable[SignerID, ArrayList[SignerInformation]]

        /// <summary>
        /// Create a store containing a single SignerInformation object.
        /// </summary>
        /// <param name="signerInfo">The signer information to contain.</param>
        public SignerInformationStore(
            SignerInformation signerInfo)
        {
            this.all = new List<SignerInformation>(1);
            this.all.Add(signerInfo);

            SignerID sid = signerInfo.SignerID;

            table[sid] = all;
        }

        /// <summary>
        /// Create a store containing a collection of SignerInformation objects.
        /// </summary>
        /// <param name="signerInfos">A collection of signer information objects to contain.</param>
        public SignerInformationStore(
            ICollection<SignerInformation> signerInfos)
        {
            foreach (SignerInformation signer in signerInfos)
            {
                SignerID sid = signer.SignerID;
                IList list = (IList)table[sid];

                if (list == null)
                {
                    table[sid] = list = Platform.CreateArrayList(1);
                }

                list.Add(signer);
            }

            this.all = new List<SignerInformation>(signerInfos);
        }

        /// <summary>The number of signers in the collection.</summary>
        public int Count
        {
            get { return all.Count; }
        }

        public SignerInformation this[SignerID selector]
        {
            get { return GetFirstMatch(selector); }
        }

        /// <returns>An ICollection of all signers in the collection</returns>
        public ICollection<SignerInformation> GetAll()
        {
            return new List<SignerInformation>(all);
        }

        /**
* Return the first SignerInformation object that matches the
* passed in selector. Null if there are no matches.
*
* @param selector to identify a signer
* @return a single SignerInformation object. Null if none matches.
*/
        public SignerInformation GetFirstMatch(
            ISelector<SignerInformation> selector)
        {
            IList<SignerInformation> list = (IList<SignerInformation>)table[selector];

            return list == null ? null : (SignerInformation)list[0];
        }

        public ICollection<SignerInformation> GetMatches(ISelector<SignerInformation> selector)
        {
            IList<SignerInformation> list = (IList<SignerInformation>)table[selector];

            return list == null ? new List<SignerInformation>(0) : new List<SignerInformation>(list);
        }
    }
}
