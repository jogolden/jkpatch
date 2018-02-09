using System;

namespace librpc
{
    public class ProcessInfo
    {
        public class VirtualMemoryEntry
        {
            public string name;
            public ulong start;
            public ulong end;
            public ulong offset;
            public uint prot;
        }

        public int pid;
        public VirtualMemoryEntry[] entries;

        public ProcessInfo(int pid, VirtualMemoryEntry[] entries)
        {
            this.pid = pid;
            this.entries = entries;
        }
    }
}
