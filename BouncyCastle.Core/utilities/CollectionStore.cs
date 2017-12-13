using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities
{
    public class CollectionStore<T>: IStore<T>
    {
        private readonly List<T> _local;

        public CollectionStore(ICollection<T> collection)
        {
            _local = new List<T>(collection);
        }

        public ICollection<T> GetMatches(ISelector<T> selector)
        {
            if (selector == null)
            {
                return new List<T>(_local);
            }
            else
            {
                List<T> col = new List<T>();
                IEnumerator<T> iter = _local.GetEnumerator();

                while (iter.MoveNext())
                {
                    T obj = iter.Current;
                    if (selector.Match(obj))
                    {
                        col.Add(obj);
                    }
                }

                return col;
            }
        }
    }
}
